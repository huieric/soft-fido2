# Copyrite IBM 2022, 2025
# IBM Confidential

from multiprocessing.synchronize import Lock


import base64, multiprocessing, os, threading, time, secrets, typing, logging, math, queue
import cbor2 as cbor
from enum import Enum, IntEnum
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


from .message_queues import QueueMessageType, MessageQueue
from .uhid_device import BaseStructure, bcolors, colour_print, dump_bytes
from .key_pair import KeyPair, KeyUtils
from .authenticator import Fido2Authenticator
from .symmetric_key import SymmetricKey
from .qt.ux.config import PlatformConfig
from .u2f_authenticator import U2FAuthenticator

#max usb data frame size
MAX_DATA_FRAME = 64

class AuthenticatorAPI(object):
    '''
    Implementation of CTAP2 authenticator commands:

    getInfo
    makeCredential
    getNextAssertion
    clientPin
    authenticatorSelection
    '''

    _exp_time: int = 30

    _open_keys = {}

    _watchdog = None
    _lock: Lock = multiprocessing.Lock()

    _pin_retry: int = 5

    _quit: bool = False
    
    # Biometric + TPM mode state
    _biometric_tpm_mode_enabled: bool = False
    _biometric_tpm_mode_lock: threading.Lock = threading.Lock()

    def __new__(cls):
        cls._watchdog = threading.Thread(target=cls._token_expiry_check)
        cls._watchdog.start()

    @classmethod
    def _token_expiry_check(cls):
        '''
        Ejects expired in-memory passkeys handled by open CIDs
        '''
        while not cls._quit:
            time.sleep(0.005)
            if not cls._lock.acquire():
                return # denied
            cid_list = list(cls._open_keys.keys())
            for cid in cid_list:
                if math.floor(time.time() - cls._open_keys[cid]["tStart"]) == cls._exp_time:
                    cls._open_keys.pop(cid)
                    colour_print(colour=bcolors.FAIL, component='Authenticator_token_expiry_check',
                                 msg='CID {} has expired!\nExisting tokens: {}'.format(cid, cls._open_keys))
            cls._lock.release()


    @classmethod
    def has_cached_up(cls, cid) -> bool:
        if not cls._lock.acquire():
            return False # denied
        try:
            if cid in cls._open_keys:
                cached_up = cls._open_keys[cid].get("upv") in ("present", "verified")
                colour_print(colour=bcolors.OKBLUE, component='AuthenticatorAPI.has_cached_up',
                            msg=f'CID {cid.hex()} exists in _open_keys, UP={cached_up}')
                return cached_up
            colour_print(colour=bcolors.WARNING, component='AuthenticatorAPI.has_cached_up',
                        msg=f'CID {cid.hex()} NOT in _open_keys')
            return False
        finally:
            cls._lock.release()

    @classmethod
    def get_user_state(cls, cid) -> str:
        """Get the user authentication state for a CID.

        Args:
            cid: Channel ID

        Returns:
            "verified" if user is fully verified (PIN or biometric)
            "present" if user presence only (UP only)
            "unknown" if CID not found or upv not yet set
        """
        cls._lock.acquire()
        try:
            if cid in cls._open_keys:
                user_state = cls._open_keys[cid].get("upv", "unknown")
                colour_print(colour=bcolors.OKBLUE, component='AuthenticatorAPI.get_user_state',
                            msg=f'CID {cid.hex()} user state: {user_state}')
                return user_state
            colour_print(colour=bcolors.WARNING, component='AuthenticatorAPI.get_user_state',
                        msg=f'CID {cid.hex()} NOT in _open_keys')
            return "unknown"
        finally:
            cls._lock.release()

    @classmethod
    def cache_up(cls, cid, user_state: str):
        """Cache user presence/verification state.

        Args:
            cid: Channel ID
            user_state: Either "verified" (full UV) or "present" (UP only)
        """
        with cls._lock:
            if cid in cls._open_keys:
                cls._open_keys[cid]["upv"] = user_state
                colour_print(colour=bcolors.OKGREEN, component='AuthenticatorAPI.cache_up',
                            msg=f'Updated CID entry: upv={user_state} for CID {cid.hex()}')
            else:
                cls._open_keys[cid] = {
                    "upv": user_state,
                    "tStart": time.time()
                }
                colour_print(colour=bcolors.OKGREEN, component='AuthenticatorAPI.cache_up',
                            msg=f'Created CID entry: upv={user_state} for CID {cid.hex()}')

    @classmethod
    def initialize_biometric_tpm_mode(cls):
        """Initialize and validate biometric + TPM mode.
        
        This mode enables seamless authentication when both:
        - Biometric device (fingerprint) is available
        - TPM device is available with platform key
        
        Returns:
            True if mode successfully enabled, False otherwise
        """
        with cls._biometric_tpm_mode_lock:
            try: # Check biometric device
                from soft_fido2.platform import get_biometric_device as get_fprint_device
                if not get_fprint_device().is_available():
                    colour_print(colour=bcolors.WARNING,
                               component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                               msg='Biometric device not available')
                    cls._biometric_tpm_mode_enabled = False
                    return False
                colour_print(colour=bcolors.OKGREEN,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg='Biometric device available')
            except ImportError:
                colour_print(colour=bcolors.WARNING,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg='D-Bus Python bindings not installed')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            try: # Check TPM device
                from soft_fido2.platform import TPMBackend as TPMDevice
                if not TPMDevice.is_available():
                    colour_print(colour=bcolors.WARNING,
                               component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                               msg='TPM device not available')
                    cls._biometric_tpm_mode_enabled = False
                    return False
            except ImportError:
                colour_print(colour=bcolors.WARNING,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg='TPM module not available')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            try: # Verify TPM key exists
                from soft_fido2.key_pair import KeyUtils
                tpm_key = KeyUtils._get_platform_kp()
                if tpm_key is None:
                    colour_print(colour=bcolors.FAIL,
                               component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                               msg='TPM key not available')
                    cls._biometric_tpm_mode_enabled = False
                    return False
            except Exception as e:
                colour_print(colour=bcolors.FAIL,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg=f'TPM key check failed: {e}')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            cls._biometric_tpm_mode_enabled = True
            colour_print(colour=bcolors.OKGREEN,
                       component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                       msg='Biometric + TPM mode enabled')
            return True
    
    @classmethod
    def is_biometric_tpm_mode_enabled(cls) -> bool:
        """Check if biometric + TPM mode is enabled."""
        with cls._biometric_tpm_mode_lock:
            return cls._biometric_tpm_mode_enabled

    @classmethod
    def _get_or_create_pin_token_kp(cls, cid: bytes) -> KeyPair:
        """
        Get or create pin token key pair for this CID.
        This is called during get_pin_cose_key() before PIN validation.
        """
        with cls._lock:
            if cid not in cls._open_keys:
                cls._open_keys[cid] = {
                    'pin_token_kp': KeyPair.generate_ecdsa(),
                    'tStart': time.time()
                }
            elif 'pin_token_kp' not in cls._open_keys[cid]:
                # Add pin token key to existing CID entry
                cls._open_keys[cid]['pin_token_kp'] = KeyPair.generate_ecdsa()
            
            return cls._open_keys[cid]['pin_token_kp']

    @classmethod
    def get_pin_auth_token(cls, cid):
        cls._lock.acquire()
        try:
            open_key = AuthenticatorAPI._open_keys.get(cid, {})
            return open_key.get('pinAuth')
        finally:
            cls._lock.release()

    @classmethod
    def _validate_pin(cls, pinHash: bytes, cid: bytes) -> typing.Optional[bytes]:
        """
        Validates a PIN by attempting to decrypt passkey files in the FIDO_HOME directory.
        
        If a valid passkey file is found, it loads the certificate and key pair,
        stores the information in the class's _open_keys dictionary with the channel
        id as the key, and returns a generated PIN authentication token.
        
        Args:
            pinHash: The hash of the PIN to validate
            cid: The channel ID to associate with the opened keys
            
        Returns:
            A PIN authentication token if validation succeeds, None otherwise
        """
        # Check if FIDO_HOME environment variable exists and directory is accessible
        if not cls._is_fido_home_valid():
            return None
        fido_home_dir = os.path.realpath(os.environ["FIDO_HOME"])
        for passkey_file in cls._get_passkey_files(fido_home_dir):
            try:
                return cls._process_passkey_file(passkey_file, pinHash, cid)
            except Exception as e:
                colour_print(
                    colour=bcolors.WARNING, 
                    component='Authenticator_validate_pin',
                    msg=f'Failed to process {os.path.basename(passkey_file)}:\n{e}'
                )
                continue
        
        colour_print(
            colour=bcolors.FAIL, 
            component='Authenticator_validate_pin',
            msg='No valid pin found!'
        )
        return None

    @classmethod
    def _is_fido_home_valid(cls) -> bool:
        """
        Checks if the FIDO_HOME environment variable exists and points to a valid directory.
        
        Returns:
            bool: True if FIDO_HOME is valid, False otherwise
        """
        if "FIDO_HOME" not in os.environ:
            logging.debug("FIDO_HOME not set, can't do much . . .")
            return False
            
        fido_home_dir = os.path.realpath(os.environ["FIDO_HOME"])
        if not os.path.exists(fido_home_dir):
            logging.debug("FIDO_HOME directory not found, can't do much . . .")
            return False
            
        return True

    @classmethod
    def _get_passkey_files(cls, directory: str) -> typing.List[str]:
        """
        Returns a list of valid .passkey files in the specified directory.
        Only returns .passkey files that have corresponding .stash files.
        
        Args:
            directory: The directory to search for .passkey files
            
        Returns:
            A list of full paths to .passkey files
        """
        passkey_files = []
        for filename in os.listdir(directory):
            if filename.endswith('.passkey'):
                passkey_path = os.path.join(directory, filename)
                
                # Check for corresponding .stash file
                base_name = filename[:-8]  # Remove .passkey
                stash_path = os.path.join(directory, base_name + '.stash')
                
                if os.path.exists(stash_path):
                    passkey_files.append(passkey_path)
                else:
                    colour_print(
                        colour=bcolors.WARNING,
                        component='Authenticator_validate_pin',
                        msg=f'{filename} missing corresponding .stash file'
                    )
            elif not filename.endswith('.stash'):
                colour_print(
                    colour=bcolors.WARNING,
                    component='Authenticator_validate_pin',
                    msg=f'{filename} has invalid file type'
                )
        return passkey_files

    @classmethod
    def _validate_and_create_keypair(cls, passkey, passkey_file):
        """
        Validates passkey structure and creates KeyPair.
        
        Args:
            passkey: Decrypted passkey dictionary
            passkey_file: Path to passkey file (for error messages)
            
        Returns:
            Tuple of (x5c certificate bytes, KeyPair instance)
            
        Raises:
            ValueError: If key is not valid
        """
        ca_x5c = passkey.get('x5c')
        key = passkey.get('key')
        
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return ca_x5c, KeyPair(key, key.public_key())
        
        raise ValueError(
            f"Key in {passkey_file} must be an EllipticCurvePrivateKey or KeyPair, got {type(key)}. "
            f"The passkey file may be corrupted. Please recreate it."
        )

    @classmethod
    def _process_passkey_file(cls, passkey_file: str, pinHash: bytes, cid: bytes) -> typing.Optional[bytes]:
        """
        Attempts to decrypt and process a passkey file.
        
        Args:
            passkey_file: Path to the passkey file
            pinHash: The hash of the PIN to validate
            cid: The channel ID to associate with the opened keys
            
        Returns:
            A PIN authentication token if processing succeeds, None otherwise
            
        Raises:
            Various exceptions if file processing fails
        """
        passkey = KeyUtils._load_passkey(pinHash, passkey_file) 
        colour_print(
            colour=bcolors.OKPINK, 
            component='Authenticator_validate_pin',
            msg='Pin decrypted a .passkey file'
        )
        ca_x5c, key_pair = cls._validate_and_create_keypair(passkey, passkey_file)
        cls._pin_retry = 5
        
        # Generate authentication token
        pin_auth_token = secrets.token_bytes(32)

        with cls._lock:
            existing_pin_token_kp = cls._open_keys.get(cid, {}).get('pin_token_kp')

            cls._open_keys[cid] = {
                'x5c': ca_x5c,
                'kp': key_pair,
                'file': passkey_file,
                'ph': pinHash,
                'pinAuth': pin_auth_token,
                'pin_token_kp': existing_pin_token_kp,  # Preserve the pin_token_kp
                'upv': 'verified',   # Correct PIN constitutes UV
                'tStart': time.time() # Extend the expiry time
            }
            return pin_auth_token


    @classmethod
    def get_pin_cose_key(cls, pin_req, cid):
        """
        Return the authenticator's public key for PIN protocol.
        """
        pin_token_kp = cls._get_or_create_pin_token_kp(cid)
        return {1: KeyUtils.get_cose_key(pin_token_kp.get_public(), hashes.SHA256(), eckx=True)}

    @classmethod
    def get_pin_retries(cls, pin_req, cid):
        # authenticatorClientPIN/getPinRetries is a read-only query. Chromium
        # may issue it repeatedly while probing/restarting a WebAuthn
        # ceremony; decrementing here incorrectly exhausted the PIN retries
        # before the user supplied a PIN.
        return {3: cls._pin_retry}

    @classmethod
    def decapsulate(cls, ecCoseKey, cid: bytes):
        """
        Perform ECDH key exchange using the per-CID pin token key.
        """
        cose_type_to_curve_map = { #These are kind of made up, as per
        #https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1
                    -25: ec.SECP256R1,
                    -26: ec.SECP521R1
                }
        ec_pub_numbs = ec.EllipticCurvePublicNumbers(KeyUtils._bytes_to_long(ecCoseKey[-2]),
                            KeyUtils._bytes_to_long(ecCoseKey[-3]),
                            cose_type_to_curve_map[ecCoseKey[3]]())
        pubkey = ec_pub_numbs.public_key()
        with cls._lock:
            if cid not in cls._open_keys or 'pin_token_kp' not in cls._open_keys[cid]:
                raise ValueError(f"Pin token key not found for CID {cid.hex()}")
            pin_token_kp = cls._open_keys[cid]['pin_token_kp']
        
        shared_point = pin_token_kp.get_private().exchange(ec.ECDH(), pubkey)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(shared_point)
        return hasher.finalize()

    @classmethod
    def get_pin_token(cls, pin_req, cid):
        #https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinToken
        logging.debug(f"pin_req: {pin_req}")
        platform_cose_key = pin_req[3]
        pin_hash_enc = pin_req[6]
        colour_print(colour=bcolors.OKPINK, component='Authenticator.get_pin_token',
                     msg='plat cose key: {}; pinHashEnc: {}'.format(platform_cose_key, pin_hash_enc))
        sharedSecret = cls.decapsulate(platform_cose_key, cid)
        colour_print(colour=bcolors.OKPINK, component='Authenticator.get_pin_token',
                     msg='shared secret: {};'.format(sharedSecret))
        cipher = Cipher(algorithms.AES256(sharedSecret), modes.CBC(bytes([0] * 16))) # nosemgrep part of the CTAP2 spec
        decryptor = cipher.decryptor() # nosemgrep
        pin_hash = decryptor.update(pin_hash_enc) + decryptor.finalize()
        pinAuthToken = cls._validate_pin(pin_hash, cid)
        if pinAuthToken != None:
            encryptor = cipher.encryptor()
            pinAuthTokenEnc = encryptor.update(pinAuthToken) + encryptor.finalize()
            return {2: pinAuthTokenEnc}
        return None

    @classmethod
    def _validate_cid(cls, cid) -> bool:
        """Validate that CID exists in open keys."""
        return cid in cls._open_keys

    @classmethod
    def _validate_ca_keypair(cls, ca_kp) -> bool:
        """Validate that CA keypair is valid KeyPair instance."""
        return isinstance(ca_kp, KeyPair)

    @classmethod
    def _resolve_passkey(cls, options, cid):
        """
        Resolve the signing keypair based on user authentication strength.
        Preference unlocked .passkey file

        Returns: (passkey_dict, resident_creds, attestation_type, request_rk)
        """
        options = options or {}
        req_rk = options.get('rk', False)
        user_state = cls.get_user_state(cid)
        if user_state == "verified":
            passkey = cls._open_keys[cid] # Strongest path: user was verified via PIN/biometric
            if isinstance(passkey, dict) and 'ph' in passkey:
                colour_print(colour=bcolors.OKGREEN, component='AuthenticatorAPI._resolve_passkey',
                            msg='UV context - using pin protected .passkey file key')
                res_creds = KeyUtils._load_passkey(passkey['ph'],
                                                passkey['file']).get('res.creds')
                return passkey, res_creds, 'packed', req_rk
        else:
            colour_print(colour=bcolors.OKGREEN, component='AuthenticatorAPI._resolve_passkey',
                        msg='UP context - using platform key')
        return { # Fallback: use platform key
            'kp': KeyUtils._get_platform_kp()
        }, None, 'packed-self', False


    @classmethod
    def _check_credential_excluded(cls, rp_id: str, user_id: bytes, res_creds) -> bool:
        """
        Check if credential already exists for rpID:userID combination.
        Returns True if credential should be excluded.
        """
        if not res_creds:
            return False
        
        for cred in res_creds:
            if rp_id == cred['rp.id'] and user_id == cred['user.id']:
                colour_print(
                    colour=bcolors.FAIL,
                    component='Authenticator.attestation_out',
                    msg=f'existing rpID and userID found: {rp_id}, {user_id}'
                )
                return True
        
        return False

    @classmethod
    def _select_algorithm(cls, pubKeyCredParams) -> int:
        """Select the best supported COSE algorithm from pubKeyCredParams.
        
        maybe try ML-DSA-44 (-48) if ES256 (-7) not offered.
        
        Args:
            pubKeyCredParams: List of public key credential parameters from the RP
            
        Returns:
            int: Selected COSE algorithm identifier
        """
        supported_algs = [
            int(param.get("alg"))
            for param in pubKeyCredParams
            if param.get("type") == "public-key"
        ]
        if -7 in supported_algs:
            return -7
        if -48 in supported_algs:
            return -48 #TODO check support for cert chain EC -> PQC
        # Fallback to ES256 if nothing matches
        return -7

    @classmethod
    def _get_hkdf_info(cls) -> str:
        """Load configured info string from platform configuration."""
        fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        return PlatformConfig(fido_home).info_string

    @classmethod
    def _create_authenticator(cls, rp_id: str, passkey, pubKeyCredParams) -> tuple[Fido2Authenticator, bytes]:
        """
        Create authenticator and derrive key.
        
        Args:
            rp_id: Relying party identifier
            passkey: Passkey data containing master key
            pubKeyCredParams: Public key credential parameters from RP
            
        Returns:
            tuple: (authenticator, keypair, credential_id)
        """
        ca_kp = passkey.get('kp')
        if ca_kp is None or not isinstance(ca_kp, KeyPair):
            raise RuntimeError("Corrupted Passkey Data")
        
        seed = KeyUtils.get_passkey_seed(
            rp_id.encode(),
            ca_kp if hasattr(ca_kp, 'is_tpm') else ca_kp.get_private(),
            info=cls._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())
        
        authenticator = Fido2Authenticator(
            caKeyPair=ca_kp,
            caCert=passkey.get('x5c'),
            sKey=skey
        )
        
        cred_id = authenticator._get_credential_id_bytes(authenticator.kp)

        logging.debug(f"RP ID: {rp_id}")
        logging.debug(f"Credential ID (hex): {cred_id.hex()}")
        
        return authenticator, cred_id

    @classmethod
    def attestation_out(cls, clientDataHash, rp, user, pkCredsParams, excludeList, exts, options, cid):
        colour_print(colour=bcolors.OKPINK, component='Authenticator.attestation_out',
                     msg='open keys: {}'.format(cls._open_keys))

        try:
            passkey, res_creds, attestation, req_rk = cls._resolve_passkey(options, cid)
        except PermissionError as e:
            colour_print(colour=bcolors.FAIL, component='Authenticator.attestation_out', msg=str(e))
            return CBORCommand.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED, None, None
        ca_kp = passkey.get('kp')
        if not cls._validate_ca_keypair(ca_kp):
            colour_print(
                colour=bcolors.OKPINK,
                component='Authenticator.attestation_out',
                msg="panic!"
            )
            return CBORCommand.CBORStatusCode.CTAP1_ERR_OTHER, None, None
        
        if cls._check_credential_excluded(rp['id'], user['id'], res_creds):
            return CBORCommand.CBORStatusCode.CTAP2_ERR_CREDENTIAL_EXCLUDED, None, None

        authenticator, cred_id = cls._create_authenticator(rp['id'], passkey, pkCredsParams)
        authData = authenticator.build_authenticator_data({'rp': rp}, 
                                attestation, authenticator.kp, uv=True, up=True, be=False, bs=False)
        colour_print(colour=bcolors.OKPINK, component='Authenticator.attestation_out',
                    msg=f'credId: {cred_id}; toSign: {base64.b64encode(bytes([*authData, *clientDataHash])).decode()}')
        attStmt = authenticator.process_attestation_statement(attestation,
                                                    clientDataHash, authData, None, authenticator.kp)
        colour_print(colour=bcolors.OKPINK, component='Authenticator.attestation_out', 
                     msg='attStmt: {}'.format(attStmt))
        if req_rk == True:
            colour_print(colour=bcolors.OKPINK, component='Authenticator.attestation_out',
                    msg=f"Storing resident credential in {passkey['file']}")
            KeyUtils.update_passkey({'cred.id': cred_id, 'user.id': user['id'], 'rp.id': rp['id']},
                                    passkey['ph'], passkey['file'])
        return None, authData, attStmt


    @classmethod
    def _maybe_next_assertion(cls, rpId, ca_kp, ca_x5c, clientDataHash, cred):
        seed = KeyUtils.get_passkey_seed(
            rpId.encode(),
            ca_kp.get_private(),
            info=cls._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())

        logging.debug(f"RP ID: {rpId}")
        logging.debug(f"Credential ID (hex): {cred.get('id').hex()}")
        colour_print(colour=bcolors.OKPINK, component='FIDO2Authenticator.assertion_outputs',
                        msg='We have a usable key, sign the challenge')
        _authenticator = Fido2Authenticator(credId=cred.get('id'), aaguid=[0] * 16,
                                            caKeyPair=ca_kp, caCert=ca_x5c, sKey=skey)
        #Generate the assertion response data
        authData = _authenticator.build_authenticator_data({'rpId': rpId}, 'packed',
                                    _authenticator.kp, True, up=True, be=False, bs=False)
        sig = _authenticator.assertion_signature(authData, clientDataHash, _authenticator.kp)
        userHandle = cred.get("user")
        credential = {
                "id": cred.get('id'),
                "type" : "public-key"
            }
        return None, credential, authData, sig, userHandle


    @classmethod
    def _maybe_platform_assertion(cls, rpId, clientDataHash, allowedList):
        plat_key = KeyUtils._get_platform_kp()
        seed = KeyUtils.get_passkey_seed(
            rpId.encode(),
            plat_key if hasattr(plat_key, 'is_tpm') else plat_key.get_private(),
            info=cls._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())
        
        for cred in allowedList:
            try:
                cred_id = cred.get('id')
                if not cred_id.startswith(Fido2Authenticator.CRED_PREFIX):
                    continue
                logging.debug(f"Credential ID (hex): {cred.get('id').hex()}")
                colour_print(colour=bcolors.OKPINK, component='FIDO2Authenticator.assertion_outputs',
                                msg='We have a usable key, sign the challenge')
                _authenticator = Fido2Authenticator(credId=cred_id, aaguid=[0] * 16,
                                                    caKeyPair=plat_key, caCert=None, sKey=skey)
                #Generate the assertion response data
                authData = _authenticator.build_authenticator_data({'rpId': rpId}, 'packed',
                                    _authenticator.kp, True, up=True, be=False, bs=False)
                sig = _authenticator.assertion_signature(authData, clientDataHash, _authenticator.kp)
                credential = {
                        "id": cred_id,
                        "type" : "public-key"
                    }
                return None, credential, authData, sig, None
            except Exception as e:
                colour_print(colour=bcolors.FAIL, component='FIDO2Authenticator.assertion_out',
                            msg=f'Could not retrieve key pair from credential id {cred} and platform KeyPair')
                logging.exception(e, stack_info=True)
                continue
        return CBORCommand.CBORStatusCode.CTAP2_ERR_NO_CREDENTIALS, None, None, None, None

    @classmethod
    def assertion_out(cls, rpId, clientDataHash, allowedList, exts, cid):
        if cid in cls._open_keys.keys() and isinstance(cls._open_keys[cid].get('kp'), KeyPair): ## Try return a res cred assertion
            passkey = cls._open_keys[cid]
            ca_x5c = passkey.get('x5c')
            ca_kp = passkey.get('kp')
            if 'ph' in passkey and 'file' in passkey:
                resCreds = KeyUtils._load_passkey(passkey['ph'],
                            passkey['file']).get('res.creds')
                if resCreds != None and isinstance(resCreds, list):
                    colour_print(colour=bcolors.OKPINK, component='FIDO2Authenticator.assertion_out',
                                msg='passkey has resident credentials, adding them to allowed list')
                    for cred in resCreds:
                        if cred.get('rp.id') == rpId:
                            allowedList += [{'id': cred.get('cred.id'), 'user': cred.get('user.id')}]
                for cred in allowedList:
                    try:
                        return cls._maybe_next_assertion(rpId, ca_kp, ca_x5c, clientDataHash, cred)
                    except Exception as e:
                        colour_print(colour=bcolors.FAIL, component='FIDO2Authenticator.assertion_out',
                                    msg=f'Could not retrieve key pair from credential id {cred}')
                        logging.exception(e, stack_info=True)
                        continue
        ## No resident or passkeyCA credentials...try platform key
        return cls._maybe_platform_assertion(rpId, clientDataHash, allowedList)


    @classmethod
    def quit(cls):
        cls._quit = True
        if cls._watchdog:
            cls._watchdog.join()

class CBORCommand(object):

    class CommandByte(Enum):
        MAKE_CREDENTIAL = 0x1
        GET_NEXT_ASSERTION = 0x2
        GET_INFO = 0x4
        CLIENT_PIN = 0x6
        RESET = 0x7
        CREDENTIAL_MANAGEMENT = 0x9
        AUTHENTICATOR_SELECTION = 0xB
        AUTHENTICATOR_CONFIG = 0xD

        def __repr__(self):
            return str(self.value)

    class CBORStatusCode(IntEnum):
        CTAP2_OK = 0x0
        CTAP1_ERR_INVALID_COMMAND = 0x01
        CTAP1_ERR_TIMEOUT = 0x05
        CTAP2_ERR_INVALID_CBOR = 0x12
        CTAP2_ERR_MISSING_PARAMETER = 0x14
        CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19
        CTAP2_ERR_OPERATION_DENIED = 0x27
        CTAP2_ERR_NO_CREDENTIALS = 0x2E
        CTAP2_ERR_PIN_INVALID = 0x31
        CTAP2_ERR_PIN_AUTH_INVALID = 0x33
        CTAP2_ERR_PUAT_REQUIRED = 0x36
        CTAP1_ERR_OTHER = 0x7F


    cid = 0xFFFFFFFF
    request = []
    response: list[int] = []
    response_segment = 0
    response_ready = False
    length = 0
    request_segment = 0
    sequence_buffer = {}  # {seq_num: bytes}
    cmd = None
    ctaphid_cmd = 0
    bcnt = 0
    _pending = None

    def __init__(self, cid, ba, skip_init=False):
        self.cid = cid
        if ba == None and skip_init == True:
            return #Create an empty command as we will directly set the response buffer later with the assigned CID.
        if len(ba) <= 1:
            colour_print(colour=bcolors.OKYELLOW, component='CBORCommand.__init__', 
                    msg="Byte Array must be at least one byte long")
        # Length of the incoming CBOR message (total).
        self.length = int.from_bytes(ba[0:2], 'big') - 1 # subtract CMD byte
        # Request buffer. This stores the incoming CBOR message and grows until all segments have been received
        self.request = ba[3:]
        # Track then number of response segments transmitted, the number transmitted in the continue sequence packet
        # should always be one less than this number
        self.response_segment = 0
        # Track the number of request segments received
        self.request_segment = 0
        self.sequence_buffer = {}
        # Response buffer. This stores the outgoing response to the received CBOR message and shrinks until the entire
        # response has been transmitted
        self.response = []
        # Command received in CTAPHID frame, this is likely 0x90 (CBOR_MSG) but might be different
        self.ctaphid_cmd = 0
        # Authenticator API command byte received in initial packet
        self.cmd = self.CommandByte(int.from_bytes(ba[2:3], 'big'))
        #Length of the payload bytes
        self.bcnt = 0
        # Signal that the response buffer is ready to be sent back to the client
        self.response_ready = False
        colour_print(colour=bcolors.OKPURPLE, component='CBORCommand.__init__', 
                msg="command {}; length {}; self.request[{}]".format(self.cmd, self.length, len(self.request)))
        # The initial CTAPHID frame may contain the complete request. Equal
        # lengths mean complete, not segmented; using >= here leaves every
        # exact-fit single-frame command (notably clientPIN/getPinRetries)
        # waiting forever for a continuation that will never arrive.
        if self.length > len(self.request):
            colour_print(colour=bcolors.OKPURPLE, component='CBORCommand.__init__', 
                    msg="request is segmented, wait for the whole message")
        else: #We have the whole message
            self.unpack()
            dump_bytes(self.response, colour=bcolors.OKPINK,
                       component='CBORCommand.__init__', msg='CTAP response')

    def append_segment(self, seg_buf, seq_num):
        """Append segment data, handling out-of-order packets.
        
        Args:
            seg_buf: Segment data bytes
            seq_num: Sequence number (required for out-of-order handling)
        """
        colour_print(colour=bcolors.OKBLUE, component='CBORCommand.append_segment',
                    msg=f'seq [{seq_num}], expecting [{self.request_segment}], len={len(self.request)}/{self.length}')
        
        # Check if this is the expected sequence
        if seq_num == self.request_segment:
            # Expected sequence - append it
            self.request_segment += 1
            self.request += seg_buf
            colour_print(colour=bcolors.OKGREEN, component='CBORCommand.append_segment',
                        msg=f'Appended seq [{seq_num}], now expecting [{self.request_segment}], len={len(self.request)}/{self.length}')
            
            # Process any buffered sequences now in order
            while self.request_segment in self.sequence_buffer:
                buffered = self.sequence_buffer.pop(self.request_segment)
                self.request_segment += 1
                self.request += buffered
                colour_print(colour=bcolors.OKGREEN, component='CBORCommand.append_segment',
                            msg=f'Processed buffered seq, now expecting [{self.request_segment}], len={len(self.request)}/{self.length}')
        elif seq_num > self.request_segment:
            # Future sequence - buffer it
            self.sequence_buffer[seq_num] = seg_buf
            colour_print(colour=bcolors.WARNING, component='CBORCommand.append_segment',
                        msg=f'Buffered out-of-order seq [{seq_num}], expecting [{self.request_segment}]')
            return
        else:
            colour_print(colour=bcolors.WARNING, component='CBORCommand.append_segment',
                        msg=f'Ignoring old/duplicate seq [{seq_num}], expecting [{self.request_segment}]')
            return
        
        # Check if message is complete
        colour_print(colour=bcolors.OKBLUE, component='CBORCommand.append_segment',
                    msg=f'Checking completion: len={len(self.request)} >= {self.length}?')
        if len(self.request) >= self.length:
            colour_print(colour=bcolors.OKGREEN, component='CBORCommand.append_segment',
                        msg='Message complete, unpacking...')
            self.unpack()
            dump_bytes(self.response, colour=bcolors.OKPINK,
                       component='CBORCommand.append_segment', msg='CTAP response')

    def _error(self, ba):
        self.response = list(self.CBORStatusCode.CTAP1_ERR_INVALID_COMMAND.to_bytes(1, 'big'))
        self.bcnt = 0
        self.response_ready = True

    #Return CBOR response if entire command has been received or None if still 
    #waiting for segments
    def unpack(self):
        if self.cmd == None:
            return self._error(None)
        return {
            self.CommandByte.MAKE_CREDENTIAL: self._make_cred,
            self.CommandByte.GET_NEXT_ASSERTION: self._get_assertion,
            self.CommandByte.GET_INFO: self._get_info,
            self.CommandByte.CLIENT_PIN: self._client_pin
            }.get(self.cmd, self._error)(bytes(self.request))

    def _set_rsp_fields(self, rsp=[]):
        self.response = rsp
        self.bcnt = len(rsp)
        self.response_ready = True

    def get_rsp_seg(self, num_bytes):
        if not isinstance(num_bytes, int):
            raise RuntimeError("panic!")
        self.response_segment += 1
        #sequence is offset by two to account for init pkt and zero index start for continue sequence
        seg_num = max(self.response_segment - 2, 0)
        colour_print(colour=bcolors.WARNING, component='CBORCommand.get_rsp_seg', 
                msg='self.response_segment = {}'.format(self.response_segment))
        colour_print(colour=bcolors.WARNING, component='CBORCommand.get_rsp_seg', 
                msg='self.response_segment - 2 = {}'.format(self.response_segment - 2))
        colour_print(colour=bcolors.WARNING, component='CBORCommand.get_rsp_seg', 
                msg='segment number = {}'.format(seg_num))
        seg = self.response
        if num_bytes >= len(self.response):
            self.response = []
        else:
            seg = self.response[:num_bytes]
            self.response = self.response[num_bytes:]
        return seg, seg_num

    @classmethod
    def set_pending(cls, pending):
        cls._pending = pending

    def prompt_for_fprint(self, result_queue):
        """
        Run fingerprint verification in parallel with GUI prompt.
        Puts result in queue when complete.
        
        Args:
            result_queue: Queue to put the verification result ('fprint', True/None)
        """
        from soft_fido2.platform import get_biometric_device as get_fprint_device, BiometricResult
        fprint_device = get_fprint_device()
        if not fprint_device.is_available():
            result_queue.put(('fprint', None))
            return
            
        colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                    msg='Starting fingerprint verification...')
        
        # Callback for when VerifyFingerSelected signal is received
        def on_finger_needed(finger_name):
            colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                        msg=f'Place {finger_name} finger on scanner')
        
        result, message = fprint_device.verify_with_retries(
            username=None,
            on_finger_needed=on_finger_needed,
            timeout=15.0,
            max_retries=3
        )
        
        if result == BiometricResult.SUCCESS:
            colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                        msg='Fingerprint verified - cancelling GUI prompt')
            MessageQueue.notify_sysapp.put(QueueMessageType.AUTH_RESPONSE)
            result_queue.put(('fprint', True)) # Cancel any pending GUI notifications
        else:
            colour_print(colour=bcolors.WARNING, component='Authenticator.gather_user_presence',
                        msg=f'Fingerprint verification failed: {message}')
            result_queue.put(('fprint', None))


    def gather_user_presence(self, context='default'):
        """
        Gather user presence with concurrent fingerprint and GUI verification.
        
        Args:
            context: Context for the UP request - 'getinfo', 'makecred', 'getassertion', or 'default'
                    This determines the keepalive status code sent to the client.
        
        Authentication adapts to credential type and UV requirements:
        - Passkey + UV Required/Preferred: PIN (already validated) + Fingerprint
        - UV Discouraged: Fingerprint only
        - 2nd Factor: Fingerprint only
        
        Both fingerprint and GUI can run concurrently. Whichever completes first wins.
        """
        if os.environ.get('SOFT_FIDO2_SKIP_UP', 'False').lower() in ['y', 'yes', '1', 'true', 't']:
            colour_print(colour=bcolors.WARNING, component='Authenticator.gather_user_presence',
                    msg='Skipping user presence check')
            AuthenticatorAPI.cache_up(self.cid, "verified")
            return True
        
        if AuthenticatorAPI.has_cached_up(self.cid):
            colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                    msg=f'Using cached UP for context: {context}')
            return True
        
        
        result_queue = queue.Queue()
        
        from soft_fido2.platform import get_biometric_device as get_fprint_device
        fprint_device = get_fprint_device()
        fprint_available = fprint_device.is_available()
        
        # Start bioauth thread if available
        fprint_thread = None
        if fprint_available:
            try:
                fprint_thread = threading.Thread(
                    target=self.prompt_for_fprint,
                    args=(result_queue,),
                    daemon=True
                )
                fprint_thread.start()
                colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                            msg='Started fingerprint verification thread')
            except ImportError:
                # D-Bus Python bindings not installed
                fprint_available = False
        
        # Start GUI prompt (always show this)
        colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                    msg=f'Starting GUI prompt for user presence (context: {context})')
        start_time = time.time()
        MessageQueue.notify_auth.queue.clear()
        MessageQueue.notify_sysapp.put(
            QueueMessageType.USER_REQUEST_FPRINT if fprint_thread is not None
            else QueueMessageType.USER_REQUEST)
  
        status_code = 0x02 # = STATUS_UPNEEDED (waiting for user presence)        
        colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                    msg=f'Starting KeepAliveWorker with status_code=0x{status_code:02x} (STATUS_UPNEEDED)')
        worker = KeepAliveWorker(self._pending, self.cid, status_code=status_code)
        worker.start()
        
        # Poll for results from either fingerprint or GUI
        gui_msg = None
        fprint_result = None
        current_time = time.time()
        
        while current_time - start_time < 15:
            time.sleep(0.002)
            current_time = time.time()
            
            # Check for fingerprint result
            if fprint_available and not fprint_result and not result_queue.empty():
                source, fprint_result = result_queue.get()
                if fprint_result:  # Fingerprint succeeded
                    colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                                msg='Fingerprint verification succeeded')
                    worker.interrupt()
                    worker.join()
                    AuthenticatorAPI.cache_up(self.cid, "verified")
                    return True
                # If fingerprint failed, continue waiting for GUI
            
            # Check for GUI click
            if MessageQueue.notify_auth.qsize() > 0:
                gui_msg = MessageQueue.notify_auth.get()
                if gui_msg == QueueMessageType.USER_RESPONSE_ACCEPT:
                    colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                                msg='GUI click accepted')
                    worker.interrupt()
                    worker.join()
                    AuthenticatorAPI.cache_up(self.cid, "verified")
                    return True
                elif gui_msg == QueueMessageType.USER_RESPONSE_ACCEPT_U2F:
                    colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                                msg='GUI click accepted (U2F mode)')
                    worker.interrupt()
                    worker.join()
                    AuthenticatorAPI.cache_up(self.cid, "present")
                    return True
                else: # User rejected, CLOSE_EVENT, or timeout. Signal the UI to dismiss the notification
                    MessageQueue.notify_sysapp.put(QueueMessageType.AUTH_RESPONSE)
                    break
        
        # Cleanup
        worker.interrupt()
        worker.join()
        time.sleep(0.002)  # Maybe wait for out to sync
        
        colour_print(colour=bcolors.FAIL, component='Authenticator.gather_user_presence',
                    msg=f'User presence denied or timeout for context: {context}')
        return False

    def _verify_pin_token(self, clientDataHash, pinUvAuthParam):
        if pinUvAuthParam not in [None, b'']:
            pinAuth = AuthenticatorAPI.get_pin_auth_token(self.cid)
            # Verify token using client data hash
            h = hmac.HMAC(pinAuth, hashes.SHA256())
            h.update(clientDataHash)
            sig = h.finalize()
            if pinUvAuthParam != sig[:16]: # valid if the first 16 bytes of sig match req pinUvAuthParam
                return False
            return True
        return False

    def _client_pin(self, ba):
        # https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorClientPIN
        pin_sub_cmds = { 
                      1: AuthenticatorAPI.get_pin_retries,
                      2: AuthenticatorAPI.get_pin_cose_key,
            #SET_PIN = 0x3
            #CHANGE_PIN = 0x4
                      5: AuthenticatorAPI.get_pin_token
                }
        req_data = cbor.loads(ba)
        colour_print(colour=bcolors.OKGREEN, component='CBORCommand._client_pin',
                     msg='Packet request: {}'.format(req_data))
        sub_cmd = req_data[2]
        colour_print(colour=bcolors.OKGREEN, component='CBORCommand._client_pin',
                     msg='pin sub_cmd: {}'.format(sub_cmd))
        rsp = pin_sub_cmds[sub_cmd](req_data, self.cid)
        result = (self.CBORStatusCode.CTAP2_ERR_PIN_INVALID).to_bytes(1, 'big')
        if rsp != None:
            result = (self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big') + cbor.dumps(rsp)
        return self._set_rsp_fields(list(result))

    # authenticatorGetInfo - now gathers user presence before returning info
    def _get_info(self, ba):
        # Gather user presence with keepalive support
        if not self.gather_user_presence(context='getinfo'):
            colour_print(colour=bcolors.FAIL, component='CBORCommand._get_info',
                        msg='User presence verification failed or denied')
            return self._set_rsp_fields(
                list((self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes(1, 'big'))
            )
        
        # Get user authentication state
        user_state = AuthenticatorAPI.get_user_state(self.cid)

        result: dict[int, typing.Any] = {
            0x01: ["FIDO_2_1", "FIDO_2_0"],
            0x02: ['hmac-secret'],
            #0x03: b"\x13\x37\xF1\xD0" * 4,
            0x03: b"\x00" * 16,
            0x04: {'rk': True, 'up': True, 'plat': False, 'clientPin': True},
            0x05: 1200,
        }

        if user_state == "verified": # Conditionally include pinProtocols based on user state
            result[0x06] = [1]  # Include PIN protocol support for verified users
            colour_print(colour=bcolors.OKBLUE, component='CBORCommand._get_info',
                        msg='Returning get_info WITH PIN protocol (user verified)')
        else:  # user_state == "present"
            result[0x01] = ["FIDO_2_0", "U2F_V2"] # Advertise CTAP1
            result[0x04] = {'up': True, 'plat': False}
            colour_print(colour=bcolors.OKBLUE, component='CBORCommand._get_info',
                        msg='Returning get_info WITHOUT PIN protocol (user present only - U2F mode)')
        
        result_bytes = bytes( (self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big') + cbor.dumps(result) )
        logging.debug(f"len: {len(result_bytes)}")
        return self._set_rsp_fields(list(result_bytes))

    def _make_cred(self, ba):
        # https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorMakeCredential
        # Verify UP/UV was already gathered during getInfo
        if not AuthenticatorAPI.has_cached_up(self.cid):
            colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                        msg='UP not cached - should have been gathered in getInfo')
            return self._set_rsp_fields(list((self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes(1, 'big')))
        
        req = cbor.loads(ba)
        colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                     msg='CBOR request {}'.format(req))
        for prop in [(0x01, 'clientDataHash'), (0x02, 'rp'), (0x03, 'user'), (0x04, 'pubkeyCredParams')]:
            if not prop[0] in req.keys():
                colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                             msg='{} missing from request:\n{}'.format(prop[1], cbor.dumps(req)))
                logging.debug("Missing required property %s" % prop[1])
                return self._set_rsp_fields( list((self.CBORStatusCode.CTAP2_ERR_MISSING_PARAMETER).to_bytes(1, 'big')) )

        # Get user authentication state and options
        options = req.get(0x07, {})
        rk_required = options.get('rk', False)
        uv_required = options.get('uv', False)        
        if uv_required and AuthenticatorAPI.get_user_state(self.cid) != "verified": # only ask for lock if uv in req
            colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                        msg='UV required by RP but not provided by user')
            return self._set_rsp_fields(list((self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes(1, 'big')))
        
        pinAuth = req.get(0x08)
        if pinAuth: # If pinAuth is present, validate it
            result = (self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes(1, 'big')
            if not self._verify_pin_token(req.get(0x01), pinAuth):
                if self.cid in AuthenticatorAPI._open_keys:
                    result = (self.CBORStatusCode.CTAP2_ERR_PIN_AUTH_INVALID).to_bytes(1, 'big')
                return self._set_rsp_fields(list(result))
        error, authData, attStmt = AuthenticatorAPI.attestation_out(req.get(0x01), req.get(0x02), req.get(0x03),
                                            req.get(0x04), req.get(0x05), req.get(0x06), 
                                            req.get(0x07, None), self.cid)
        result = (self.CBORStatusCode.CTAP1_ERR_OTHER).to_bytes(1, 'big')
        if error:
            result = error.to_bytes(1, 'big')
        if authData and attStmt:
            rsp = {
                0x01: 'packed', #fmt
                0x02: authData,
                0x03: attStmt
            }
            result = (self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big') + cbor.dumps(rsp)
        return self._set_rsp_fields(list(result))


    def _u2f_rsp(self, cid, cmd_byte: int, payload: bytes,
                 sw: bytes = b'\x90\x00') -> 'CBORCommand':
        """Build a U2F APDU response CBORCommand."""
        rsp = CBORCommand(cid, None, skip_init=True)
        rsp.ctaphid_cmd = cmd_byte
        data = payload + sw
        rsp.response = list(data)
        rsp.bcnt = len(data)
        return rsp

    def _u2f_req(self, cid, cmd_byte: int, apdu: bytes) -> 'CBORCommand':
        """
        Parse the CTAPHID_MSG APDU and dispatch to the appropriate U2F handler.
        UP is not re-checked — already established during _get_info.
        """
        u2f_cla  = apdu[0:1]
        u2f_ins  = apdu[1:2]
        u2f_p1   = apdu[2:3]
        u2f_p2   = apdu[3:4]
        lc = int.from_bytes(apdu[5:7], 'big') if len(apdu) >= 7 else 0
        u2f_data = apdu[7:7 + lc] if lc > 0 else apdu[7:]

        colour_print(colour=bcolors.OKGREEN, component='CBORCommand._u2f_req',
                     msg='CLA={}; INS={}; P1={}; P2={}; Lc={}'.format(
                         u2f_cla.hex(), u2f_ins.hex(), u2f_p1.hex(), u2f_p2.hex(), lc))
        colour_print(colour=bcolors.OKGREEN, component='CBORCommand._u2f_req',
                     msg='apdu total len={}; u2f_data len={}'.format(len(apdu), len(u2f_data)))
        if len(u2f_data) > 0:
            dump_bytes(u2f_data, colour=bcolors.OKGREEN,
                       component='CBORCommand._u2f_req', msg='u2f_data: ')

        if u2f_cla != b'\x00':
            colour_print(colour=bcolors.FAIL, component='CBORCommand._u2f_req',
                         msg='Unexpected CLA {}'.format(u2f_cla.hex()))
            return self._u2f_rsp(cid, cmd_byte, b'', sw=b'\x69\x00')

        if u2f_ins == b'\x03':
            return self._u2f_version(cid, cmd_byte)
        if u2f_ins == b'\x01':
            return self._u2f_register(cid, cmd_byte, u2f_data)
        if u2f_ins == b'\x02':
            return self._u2f_authenticate(cid, cmd_byte, u2f_p1, u2f_data)

        colour_print(colour=bcolors.FAIL, component='CBORCommand._u2f_req',
                     msg='Unknown INS {}'.format(u2f_ins.hex()))
        return self._u2f_rsp(cid, cmd_byte, b'', sw=b'\x69\x00')

    def _u2f_version(self, cid, cmd_byte: int) -> 'CBORCommand':
        return self._u2f_rsp(cid, cmd_byte, b'U2F_V2')

    def _u2f_register(self, cid, cmd_byte: int, u2f_data: bytes) -> 'CBORCommand':
        """
        Handle U2F_REGISTER (INS=0x01).

        u2f_data layout:
            [0:32]  clientDataHash
            [32:64] appIdHash
        """
        if len(u2f_data) < 64:
            colour_print(colour=bcolors.FAIL, component='CBORCommand._u2f_register',
                         msg=f'REGISTER data too short: {len(u2f_data)} bytes')
            return self._u2f_rsp(cid, cmd_byte, b'', sw=b'\x6a\x80')

        client_data_hash = u2f_data[0:32]
        app_id_hash      = u2f_data[32:64]

        colour_print(colour=bcolors.OKPURPLE, component='CBORCommand._u2f_register',
                     msg='clientDataHash={}'.format(client_data_hash.hex()))
        colour_print(colour=bcolors.OKPURPLE, component='CBORCommand._u2f_register',
                     msg='appIdHash={}'.format(app_id_hash.hex()))

        plat_kp = KeyUtils._get_platform_kp()
        seed = KeyUtils.get_passkey_seed(
            app_id_hash.hex().encode(),
            plat_kp if hasattr(plat_kp, 'is_tpm') else plat_kp.get_private(),
            info=AuthenticatorAPI._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())

        auth = U2FAuthenticator(keyPair=plat_kp, sKey=skey)
        try:
            payload = auth.register(app_id_hash, client_data_hash)
        except Exception as e:
            colour_print(colour=bcolors.FAIL, component='CBORCommand._u2f_register',
                         msg=f'register() failed: {e}')
            return self._u2f_rsp(cid, cmd_byte, b'', sw=b'\x69\x00')
        if auth.cib:
            colour_print(colour=bcolors.OKGREEN, component='CBORCommand._u2f_register',
                        msg=f'Registration complete, cred_id={auth.cib.hex()}')
        return self._u2f_rsp(cid, cmd_byte, payload)

    def _u2f_authenticate(self, cid, cmd_byte: int, p1: bytes,
                          u2f_data: bytes) -> 'CBORCommand':
        """
        Handle U2F_AUTHENTICATE (INS=0x02).

        u2f_data layout:
            [0:32]  clientDataHash
            [32:64] appIdHash
            [64]    key handle length (1 byte)
            [65:]   key handle bytes

        P1=0x07 → check-only (return 0x6985 if key handle is ours)
        P1=0x03 → sign
        """
        if len(u2f_data) < 65:
            colour_print(colour=bcolors.FAIL, component='CBORCommand._u2f_authenticate',
                         msg=f'AUTHENTICATE data too short: {len(u2f_data)} bytes')
            return self._u2f_rsp(cid, cmd_byte, b'', sw=b'\x6a\x80')

        client_data_hash = u2f_data[0:32]
        app_id_hash      = u2f_data[32:64]
        kh_len           = u2f_data[64]
        key_handle       = u2f_data[65:65 + kh_len]

        if p1 == b'\x07': # confirm we own this key handle
            if key_handle.startswith(Fido2Authenticator.CRED_PREFIX):
                return self._u2f_rsp(cid, cmd_byte, b'', sw=b'\x69\x85')
            return self._u2f_rsp(cid, cmd_byte, b'', sw=b'\x6a\x80')

        plat_kp = KeyUtils._get_platform_kp()
        seed = KeyUtils.get_passkey_seed(
            app_id_hash.hex().encode(),
            plat_kp if hasattr(plat_kp, 'is_tpm') else plat_kp.get_private(),
            info=AuthenticatorAPI._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())

        try:
            auth = U2FAuthenticator(credId=key_handle, sKey=skey)
            payload = auth.authenticate(app_id_hash, client_data_hash)
        except Exception as e:
            colour_print(colour=bcolors.FAIL, component='CBORCommand._u2f_authenticate',
                         msg=f'authenticate() failed: {e}')
            return self._u2f_rsp(cid, cmd_byte, b'', sw=b'\x69\x00')

        colour_print(colour=bcolors.OKGREEN, component='CBORCommand._u2f_authenticate',
                     msg='Authentication complete')
        return self._u2f_rsp(cid, cmd_byte, payload)

    def _get_assertion(self, ba):
        # https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetAssertion
        # Verify UP was already gathered during getInfo
        if not AuthenticatorAPI.has_cached_up(self.cid):
            colour_print(colour=bcolors.FAIL, component='CBORCommand._get_assertion',
                        msg='UP not cached - should have been gathered in getInfo')
            return self._set_rsp_fields(list((self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes(1, 'big')))
        
        req = cbor.loads(ba)
        colour_print(colour=bcolors.FAIL, component='CBORCommand._get_assertion',
                     msg='CBOR request {}'.format(req))
        for prop in [(0x01, 'rpId'), (0x02, 'clientDataHash')]:
            if not prop[0] in req:
                colour_print(colour=bcolors.FAIL, component='CBORCommand._get_assertion',
                             msg='{} missing from request:\n{}'.format(prop[1], cbor.dumps(req)))
                logging.debug("Missing required property %s" % prop[1])
                return self._set_rsp_fields( list((self.CBORStatusCode.CTAP2_ERR_MISSING_PARAMETER).to_bytes(1, 'big')) )
        
        pinAuth = req.get(0x06)
        options = req.get(0x05, {})
        uv_required = options.get('uv', False)
        if uv_required and not pinAuth: # If UV is required but pinAuth is missing, fail
            colour_print(colour=bcolors.FAIL, component='CBORCommand._get_assertion',
                        msg='UV required but pinAuth missing')
            return self._set_rsp_fields(list((self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes(1, 'big')))

        if pinAuth: # If pinAuth is present, validate it
            if not self._verify_pin_token(req.get(0x02), pinAuth):
                result = (self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes(1, 'big')
                if self.cid in AuthenticatorAPI._open_keys:
                    result = (self.CBORStatusCode.CTAP2_ERR_PIN_AUTH_INVALID).to_bytes(1, 'big')
                return self._set_rsp_fields(list(result))
        
        error, credential, authData, signature, userHandle = AuthenticatorAPI.assertion_out(req.get(0x01),
                                                req.get(0x02), req.get(0x03, []), req.get(0x04, {}), self.cid)
        result = (self.CBORStatusCode.CTAP1_ERR_OTHER).to_bytes(1, 'big')
        if error:
            result = error.to_bytes(1, 'big')
        elif credential and authData and signature:
            rsp = {
                    0x01: credential,
                    0x02: authData,
                    0x03: signature
            }
            if userHandle:
                rsp[0x04] = {'id': userHandle}
            result = (self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big') + cbor.dumps(rsp)
        return self._set_rsp_fields(list(result))


class CTAPHIDInitPkt(BaseStructure):
    """
    Init data frame
    """
    _fields_ = [
        ('cid', 'I'),
        ('cmd', 'B'),
        ('bcnt', 'H', 0)
    ]

    def __init__(self, **kwargs):
        self.base_pack_format = '>'
        if 'data' in kwargs:
            index = None
            for i, field in enumerate(self._fields_):
                if field[0] == 'data':
                    index = i
                    break
            if index == None:
                colour_print(colour=bcolors.OKGREEN, component='CTAPHIDInitPkt.__init__', msg='setting data field')
                self._fields_ += [('data', '%ds' % len(kwargs['data']))]
            else:
                colour_print(colour=bcolors.OKGREEN, component='CTAPHIDInitPkt.__init__', 
                             msg='data already exists as a field, updating it')
                self._fields_[index] = ('data', '%ds' % len(kwargs['data']))
            logging.debug(f"{self._fields_}")
        super().__init__(**kwargs)

class CTAPHIDSeqPkt(BaseStructure):
    """
    Sequence data frame
    """
    _fields_ = [
        ('cid', 'I'),
        ('seq', 'B'),
    ]

    def __init__(self, **kwargs):
        self.base_pack_format = '>'
        #logging.debug(kwargs)
        if 'data' in kwargs:
            index = None
            for i, field in enumerate(self._fields_):
                if field[0] == 'data':
                    index = i
                    break
            if index == None:
                logging.debug("setting data field")
                colour_print(colour=bcolors.OKPINK, component='CTAPHIDSeqPkt.__init__', msg='setting data field')
                self._fields_ += [('data', '%ds' % len(kwargs['data']))]
            else:
                colour_print(colour=bcolors.OKPINK, component='CTAPHIDSeqPkt.__init__', 
                             msg='data already exists as a field, updating it')
                self._fields_[index] = ('data', '%ds' % len(kwargs['data']))
            logging.debug(f"{self._fields_}")
        super(CTAPHIDSeqPkt, self).__init__(**kwargs)


class KeepAliveWorker(threading.Thread):
    """
    Background thread that sends CTAPHID keepalive messages.
    
    CTAP2 Status Codes (per CTAP2 spec Section 11.2.9.1.7):
    - 0x01: STATUS_PROCESSING - The authenticator is still processing the current request
    - 0x02: STATUS_UPNEEDED - The authenticator is waiting for user presence
    
    Note: CTAPHID_KEEPALIVE command code is 0x3B per CTAP2 specification.
    """

    cid = b'0xFFFFFFFF'
    not_alive = False
    uhid = None

    def __init__(self, pending, cid, status_code=0x02, interval_ms=100):
        """
        Initialize KeepAliveWorker.
        
        Args:
            pending: Queue to send keepalive packets to
            cid: Channel ID for the CTAPHID connection
            status_code: CTAP2 status code (0x01=processing, 0x02=waiting for UP)
            interval_ms: Interval in milliseconds between keepalive messages (default: 100ms)
        """
        super().__init__()
        self.pending = pending
        self.cid = cid
        self.status_code = status_code
        self.interval_ms = interval_ms

    def run(self):
        interval_sec = self.interval_ms / 1000.0
        while self.not_alive == False:
            time.sleep(interval_sec)
            
            # Log keepalive with status code description
            status_desc = {
                0x01: 'STATUS_PROCESSING',
                0x02: 'STATUS_UPNEEDED'
            }.get(self.status_code, f'UNKNOWN(0x{self.status_code:02x})')
            
            colour_print(colour=bcolors.FAIL, component='KeepAliveWorker.run',
                        msg=f'Sending keepalive with status {status_desc} (0x{self.status_code:02x})')
            
            # Send keepalive packet with correct CTAPHID_KEEPALIVE command (0x3B per spec)
            rsp = CTAPHIDInitPkt(cid=int.from_bytes(self.cid, 'big'),
                                  cmd=0x3B,  # CTAPHID_KEEPALIVE per CTAP2 spec
                                  bcnt=0x01,
                                  data=bytes([self.status_code])).pack()
            self.pending.put(rsp)

    def interrupt(self):
        """Stop the keepalive worker thread."""
        self.not_alive = True