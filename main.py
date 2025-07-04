import os
import sys
import time
import hmac
import json
import zlib
import base64
import struct
import secrets
import hashlib
import threading
import argparse
import numpy as np
from typing import Tuple, Dict, List, Optional, Union, Any
from dataclasses import dataclass, field
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
from ctypes import c_uint64, c_uint32, c_uint8, POINTER, Structure
import platform

if platform.system() == 'Windows':
    try:
        kernel32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll
    except:
        kernel32 = ntdll = None
else:
    kernel32 = ntdll = None

class SecurityLevel(IntEnum):
    CLASSICAL_128 = 128
    CLASSICAL_192 = 192  
    CLASSICAL_256 = 256
    QUANTUM_128 = 384
    QUANTUM_192 = 512
    QUANTUM_256 = 768
    FORTRESS = 1024

@dataclass
class CryptoParameters:
    ring_dimension: int
    coefficient_modulus: List[int]
    plaintext_modulus: int
    noise_bound: float
    security_margin: float
    
    lattice_dimension: int
    lattice_modulus: int
    gaussian_parameter: float
    rejection_bound: int
    
    code_length: int
    code_dimension: int
    minimum_distance: int
    
    hash_tree_height: int
    ots_winternitz_w: int
    ots_key_size: int
    
    multivariate_variables: int
    multivariate_equations: int
    field_size: int
    
    isogeny_prime: int
    isogeny_degree: int
    supersingular_count: int
    
    entropy_pool_size: int
    rng_reseed_interval: int
    side_channel_protection: int

class ConstantTimeOps:
    @staticmethod
    def ct_select_u64(a: int, b: int, condition: int) -> int:
        mask = (-condition) & 0xFFFFFFFFFFFFFFFF
        return (a & mask) | (b & (~mask))
    
    @staticmethod
    def ct_compare_bytes(a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        diff = 0
        for x, y in zip(a, b):
            diff |= x ^ y
        return diff == 0
    
    @staticmethod
    def ct_conditional_copy(dest: bytearray, src: bytes, condition: int):
        mask = (-condition) & 0xFF
        for i in range(len(dest)):
            if i < len(src):
                dest[i] = (dest[i] & (~mask)) | (src[i] & mask)
    
    @staticmethod
    def ct_is_zero(x: int) -> int:
        return ((x | (-x)) >> 63) ^ 1
    
    @staticmethod
    def ct_abs_diff(a: int, b: int) -> int:
        diff = a - b
        mask = diff >> 63
        return (diff ^ mask) - mask

class SecureRNG:
    def __init__(self, entropy_sources: int = 8):
        self._entropy_pool = bytearray(8192)
        self._pool_index = 0
        self._counter = 0
        self._last_reseed = time.time_ns()
        self._entropy_sources = entropy_sources
        self._lock = threading.Lock()
        self._initialize_pool()
    
    def _initialize_pool(self):
        entropy = bytearray()
        
        entropy.extend(secrets.token_bytes(1024))
        entropy.extend(struct.pack('>Q', time.time_ns()))
        entropy.extend(struct.pack('>Q', os.getpid()))
        
        if hasattr(os, 'urandom'):
            entropy.extend(os.urandom(512))
        
        if kernel32:
            try:
                entropy.extend(self._windows_entropy())
            except:
                pass
        
        try:
            with open('/dev/random', 'rb') as f:
                entropy.extend(f.read(256))
        except:
            pass
        
        entropy.extend(hashlib.sha3_512(str(threading.current_thread()).encode()).digest())
        
        for cpu_state in range(16):
            entropy.extend(struct.pack('>d', time.perf_counter()))
            entropy.extend(struct.pack('>Q', hash(str(locals())) & 0xFFFFFFFFFFFFFFFF))
        
        self._mix_entropy(entropy)
    
    def _windows_entropy(self) -> bytes:
        entropy = bytearray()
        try:
            perf_counter = ctypes.c_ulonglong()
            kernel32.QueryPerformanceCounter(ctypes.byref(perf_counter))
            entropy.extend(struct.pack('>Q', perf_counter.value))
            
            tick_count = kernel32.GetTickCount64()
            entropy.extend(struct.pack('>Q', tick_count))
        except:
            pass
        return bytes(entropy)
    
    def _mix_entropy(self, new_entropy: bytes):
        mixed = hashlib.sha3_512(bytes(self._entropy_pool) + new_entropy).digest()
        for i in range(len(mixed)):
            self._entropy_pool[i % len(self._entropy_pool)] ^= mixed[i]
        
        self._pool_index = (self._pool_index + len(new_entropy)) % len(self._entropy_pool)
    
    def _should_reseed(self) -> bool:
        current_time = time.time_ns()
        return (current_time - self._last_reseed) > 60_000_000_000 or self._counter > 1000000
    
    def get_bytes(self, length: int) -> bytes:
        with self._lock:
            if self._should_reseed():
                self._initialize_pool()
                self._last_reseed = time.time_ns()
                self._counter = 0
            
            self._counter += 1
            
            output = bytearray()
            for _ in range((length + 63) // 64):
                state = bytes(self._entropy_pool[self._pool_index:self._pool_index + 64])
                if len(state) < 64:
                    state += bytes(self._entropy_pool[:64 - len(state)])
                
                chunk = hashlib.sha3_512(state + struct.pack('>Q', self._counter)).digest()
                output.extend(chunk)
                
                self._pool_index = (self._pool_index + 13) % len(self._entropy_pool)
            
            self._mix_entropy(struct.pack('>Q', time.time_ns()))
            
            return bytes(output[:length])
    
    def get_uniform_int(self, bound: int) -> int:
        if bound <= 1:
            return 0
        
        bit_length = bound.bit_length()
        byte_length = (bit_length + 7) // 8
        mask = (1 << bit_length) - 1
        
        while True:
            candidate_bytes = self.get_bytes(byte_length)
            candidate = int.from_bytes(candidate_bytes, 'big') & mask
            if candidate < bound:
                return candidate

class DiscreteGaussian:
    def __init__(self, sigma: float, precision: int = 128, tail_bound: int = 12):
        self.sigma = sigma
        self.precision = precision
        self.tail_bound = int(tail_bound * sigma)
        self.rng = SecureRNG()
        self._build_tables()
    
    def _build_tables(self):
        self.cumulative_table = []
        self.alias_table = []
        
        bound = self.tail_bound
        probabilities = []
        
        total_prob = 0.0
        for z in range(-bound, bound + 1):
            prob = np.exp(-z * z / (2.0 * self.sigma * self.sigma))
            probabilities.append(prob)
            total_prob += prob
        
        probabilities = [p / total_prob for p in probabilities]
        
        cumulative = 0.0
        for i, prob in enumerate(probabilities):
            cumulative += prob
            self.cumulative_table.append((cumulative, i - bound))
        
        n = len(probabilities)
        scaled_probs = [p * n for p in probabilities]
        
        small = []
        large = []
        
        for i, prob in enumerate(scaled_probs):
            if prob < 1.0:
                small.append(i)
            else:
                large.append(i)
        
        prob_alias = [0.0] * n
        alias = [0] * n
        
        while small and large:
            s = small.pop()
            l = large.pop()
            
            prob_alias[s] = scaled_probs[s]
            alias[s] = l
            
            scaled_probs[l] = scaled_probs[l] - (1.0 - scaled_probs[s])
            
            if scaled_probs[l] < 1.0:
                small.append(l)
            else:
                large.append(l)
        
        while large:
            prob_alias[large.pop()] = 1.0
        
        while small:
            prob_alias[small.pop()] = 1.0
        
        self.alias_table = list(zip(prob_alias, alias))
    
    def sample(self) -> int:
        if not self.alias_table:
            u = int.from_bytes(self.rng.get_bytes(8), 'big') / (2**64)
            for cumulative, value in self.cumulative_table:
                if u <= cumulative:
                    return value
            return self.cumulative_table[-1][1]
        
        n = len(self.alias_table)
        i = self.rng.get_uniform_int(n)
        u = int.from_bytes(self.rng.get_bytes(8), 'big') / (2**64)
        
        prob, alias = self.alias_table[i]
        if u <= prob:
            return i - self.tail_bound
        else:
            return alias - self.tail_bound
    
    def sample_vector(self, length: int) -> np.ndarray:
        result = np.zeros(length, dtype=np.int64)
        for i in range(length):
            result[i] = self.sample()
        return result

class ModularArithmetic:
    @staticmethod
    def mod_add(a: int, b: int, mod: int) -> int:
        return (a + b) % mod
    
    @staticmethod
    def mod_sub(a: int, b: int, mod: int) -> int:
        return (a - b) % mod
    
    @staticmethod
    def mod_mul(a: int, b: int, mod: int) -> int:
        return (a * b) % mod
    
    @staticmethod
    def mod_exp(base: int, exp: int, mod: int) -> int:
        result = 1
        base = base % mod
        while exp > 0:
            if exp & 1:
                result = (result * base) % mod
            exp >>= 1
            base = (base * base) % mod
        return result
    
    @staticmethod
    def mod_inverse(a: int, mod: int) -> int:
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % mod, mod)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % mod + mod) % mod

class NumberTheoreticTransform:
    def __init__(self, length: int, modulus: int):
        self.length = length
        self.modulus = modulus
        self.root = self._find_primitive_root()
        self.inv_length = ModularArithmetic.mod_inverse(length, modulus)
        self._precompute_tables()
    
    def _find_primitive_root(self) -> int:
        if self.modulus == 1:
            return 0
        
        factors = self._factorize(self.modulus - 1)
        
        for g in range(2, self.modulus):
            is_primitive = True
            for factor in factors:
                if ModularArithmetic.mod_exp(g, (self.modulus - 1) // factor, self.modulus) == 1:
                    is_primitive = False
                    break
            if is_primitive:
                return ModularArithmetic.mod_exp(g, (self.modulus - 1) // self.length, self.modulus)
        
        raise ValueError("Primitive root not found")
    
    def _factorize(self, n: int) -> List[int]:
        factors = []
        d = 2
        while d * d <= n:
            while n % d == 0:
                factors.append(d)
                n //= d
            d += 1
        if n > 1:
            factors.append(n)
        return list(set(factors))
    
    def _precompute_tables(self):
        self.forward_table = []
        self.inverse_table = []
        
        root_powers = [1]
        inv_root = ModularArithmetic.mod_inverse(self.root, self.modulus)
        inv_root_powers = [1]
        
        for i in range(1, self.length):
            root_powers.append((root_powers[-1] * self.root) % self.modulus)
            inv_root_powers.append((inv_root_powers[-1] * inv_root) % self.modulus)
        
        self.forward_table = root_powers
        self.inverse_table = inv_root_powers
    
    def forward_transform(self, coefficients: np.ndarray) -> np.ndarray:
        n = len(coefficients)
        if n != self.length:
            raise ValueError("Invalid coefficient vector length")
        
        result = coefficients.copy()
        
        length = 2
        while length <= n:
            step = n // length
            for i in range(0, n, length):
                root_idx = 0
                for j in range(length // 2):
                    u = result[i + j]
                    v = (result[i + j + length // 2] * self.forward_table[root_idx]) % self.modulus
                    result[i + j] = (u + v) % self.modulus
                    result[i + j + length // 2] = (u - v) % self.modulus
                    root_idx += step
            length <<= 1
        
        return result
    
    def inverse_transform(self, coefficients: np.ndarray) -> np.ndarray:
        n = len(coefficients)
        if n != self.length:
            raise ValueError("Invalid coefficient vector length")
        
        result = coefficients.copy()
        
        length = n
        while length >= 2:
            step = n // length
            for i in range(0, n, length):
                root_idx = 0
                for j in range(length // 2):
                    u = result[i + j]
                    v = result[i + j + length // 2]
                    result[i + j] = (u + v) % self.modulus
                    result[i + j + length // 2] = ((u - v) * self.inverse_table[root_idx]) % self.modulus
                    root_idx += step
            length >>= 1
        
        for i in range(n):
            result[i] = (result[i] * self.inv_length) % self.modulus
        
        return result

class RingPolynomial:
    def __init__(self, coefficients: np.ndarray, modulus: int):
        self.coefficients = coefficients % modulus
        self.modulus = modulus
        self.degree = len(coefficients)
        self.ntt = NumberTheoreticTransform(self.degree, modulus)
    
    def __add__(self, other: 'RingPolynomial') -> 'RingPolynomial':
        if self.degree != other.degree or self.modulus != other.modulus:
            raise ValueError("Incompatible polynomials")
        
        result = (self.coefficients + other.coefficients) % self.modulus
        return RingPolynomial(result, self.modulus)
    
    def __sub__(self, other: 'RingPolynomial') -> 'RingPolynomial':
        if self.degree != other.degree or self.modulus != other.modulus:
            raise ValueError("Incompatible polynomials")
        
        result = (self.coefficients - other.coefficients) % self.modulus
        return RingPolynomial(result, self.modulus)
    
    def __mul__(self, other: 'RingPolynomial') -> 'RingPolynomial':
        if self.degree != other.degree or self.modulus != other.modulus:
            raise ValueError("Incompatible polynomials")
        
        a_ntt = self.ntt.forward_transform(self.coefficients)
        b_ntt = self.ntt.forward_transform(other.coefficients)
        
        c_ntt = (a_ntt * b_ntt) % self.modulus
        result = self.ntt.inverse_transform(c_ntt)
        
        return RingPolynomial(result, self.modulus)
    
    def scalar_mul(self, scalar: int) -> 'RingPolynomial':
        result = (self.coefficients * scalar) % self.modulus
        return RingPolynomial(result, self.modulus)
    
    def to_bytes(self) -> bytes:
        return b''.join(struct.pack('>Q', int(c)) for c in self.coefficients)
    
    @classmethod
    def from_bytes(cls, data: bytes, modulus: int) -> 'RingPolynomial':
        coeffs = []
        for i in range(0, len(data), 8):
            chunk = data[i:i+8]
            if len(chunk) == 8:
                coeffs.append(struct.unpack('>Q', chunk)[0])
        return cls(np.array(coeffs, dtype=np.int64), modulus)

class AdvancedErrorCorrection:
    def __init__(self, n: int, k: int, t: int):
        self.n = n
        self.k = k
        self.t = t
        self.field_size = 256
        self._build_log_antilog_tables()
        self._build_generator_polynomial()
    
    def _build_log_antilog_tables(self):
        self.log_table = [0] * self.field_size
        self.antilog_table = [0] * self.field_size
        
        x = 1
        for i in range(self.field_size - 1):
            self.antilog_table[i] = x
            self.log_table[x] = i
            x <<= 1
            if x & self.field_size:
                x ^= 0x11d
    
    def _gf_mult(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return self.antilog_table[(self.log_table[a] + self.log_table[b]) % (self.field_size - 1)]
    
    def _gf_div(self, a: int, b: int) -> int:
        if a == 0:
            return 0
        if b == 0:
            raise ValueError("Division by zero in GF")
        return self.antilog_table[(self.log_table[a] - self.log_table[b]) % (self.field_size - 1)]
    
    def _gf_pow(self, a: int, exp: int) -> int:
        if a == 0:
            return 0
        return self.antilog_table[(self.log_table[a] * exp) % (self.field_size - 1)]
    
    def _build_generator_polynomial(self):
        self.generator = [1]
        for i in range(2 * self.t):
            new_gen = [0] * (len(self.generator) + 1)
            alpha_i = self.antilog_table[i % (self.field_size - 1)]
            
            for j in range(len(self.generator)):
                new_gen[j] ^= self.generator[j]
                new_gen[j + 1] ^= self._gf_mult(self.generator[j], alpha_i)
            
            self.generator = new_gen
    
    def encode(self, data: bytes) -> bytes:
        if len(data) > self.k:
            raise ValueError("Data too large")
        
        padded_data = data + bytes(self.k - len(data))
        message = list(padded_data) + [0] * (self.n - self.k)
        
        for i in range(self.k):
            if message[i] != 0:
                coeff = message[i]
                for j in range(len(self.generator)):
                    message[i + j] ^= self._gf_mult(coeff, self.generator[j])
        
        return bytes(message)
    
    def decode(self, received: bytes) -> Optional[bytes]:
        if len(received) != self.n:
            return None
        
        received = list(received)
        syndromes = self._compute_syndromes(received)
        
        if all(s == 0 for s in syndromes):
            return bytes(received[:self.k])
        
        error_locator = self._berlekamp_massey(syndromes)
        if not error_locator:
            return None
        
        error_positions = self._find_error_positions(error_locator)
        if len(error_positions) > self.t:
            return None
        
        error_magnitudes = self._compute_error_magnitudes(syndromes, error_positions)
        
        for pos, mag in zip(error_positions, error_magnitudes):
            received[pos] ^= mag
        
        return bytes(received[:self.k])
    
    def _compute_syndromes(self, received: List[int]) -> List[int]:
        syndromes = []
        for i in range(2 * self.t):
            syndrome = 0
            alpha_i = self.antilog_table[i % (self.field_size - 1)]
            alpha_power = 1
            
            for j in range(self.n):
                syndrome ^= self._gf_mult(received[j], alpha_power)
                alpha_power = self._gf_mult(alpha_power, alpha_i)
            
            syndromes.append(syndrome)
        
        return syndromes
    
    def _berlekamp_massey(self, syndromes: List[int]) -> List[int]:
        n = len(syndromes)
        c = [1] + [0] * n
        b = [1] + [0] * n
        l = 0
        m = 1
        
        for i in range(n):
            d = syndromes[i]
            for j in range(1, l + 1):
                if j < len(c):
                    d ^= self._gf_mult(c[j], syndromes[i - j])
            
            if d == 0:
                m += 1
            else:
                t = c[:]
                
                for j in range(len(b)):
                    if i + j < len(c):
                        c[i + j] ^= self._gf_mult(d, b[j])
                
                if 2 * l <= i:
                    l = i + 1 - l
                    for j in range(len(t)):
                        if j < len(b):
                            b[j] = self._gf_div(t[j], d) if d != 0 else 0
                    m = 1
                else:
                    m += 1
        
        return c[:l+1]
    
    def _find_error_positions(self, error_locator: List[int]) -> List[int]:
        positions = []
        for i in range(self.n):
            alpha_inv_i = self.antilog_table[(-i) % (self.field_size - 1)]
            result = 0
            alpha_power = 1
            
            for coeff in error_locator:
                result ^= self._gf_mult(coeff, alpha_power)
                alpha_power = self._gf_mult(alpha_power, alpha_inv_i)
            
            if result == 0:
                positions.append(i)
        
        return positions
    
    def _compute_error_magnitudes(self, syndromes: List[int], positions: List[int]) -> List[int]:
        magnitudes = []
        for pos in positions:
            numerator = 0
            denominator = 1
            
            alpha_i = self.antilog_table[pos % (self.field_size - 1)]
            alpha_power = 1
            
            for syndrome in syndromes:
                numerator ^= self._gf_mult(syndrome, alpha_power)
                alpha_power = self._gf_mult(alpha_power, alpha_i)
            
            for other_pos in positions:
                if other_pos != pos:
                    alpha_j = self.antilog_table[other_pos % (self.field_size - 1)]
                    denominator = self._gf_mult(denominator, 
                                               self.antilog_table[(pos - other_pos) % (self.field_size - 1)])
            
            magnitude = self._gf_div(numerator, denominator) if denominator != 0 else 0
            magnitudes.append(magnitude)
        
        return magnitudes

class HybridSignature:
    def __init__(self, tree_height: int, ots_w: int):
        self.tree_height = tree_height
        self.ots_w = ots_w
        self.rng = SecureRNG()
        self.signature_count = 0
        self.max_signatures = 2 ** tree_height
        
    def keygen(self) -> Tuple[bytes, bytes]:
        master_seed = self.rng.get_bytes(64)
        
        leaf_keys = []
        for i in range(self.max_signatures):
            leaf_seed = hashlib.sha3_512(master_seed + struct.pack('>Q', i)).digest()
            sk_ots = self._ots_keygen(leaf_seed)
            pk_ots = self._ots_derive_public_key(sk_ots)
            leaf_keys.append(hashlib.sha3_256(pk_ots).digest())
        
        tree_nodes = self._build_merkle_tree(leaf_keys)
        root = tree_nodes[0][0]
        
        private_key = {
            'master_seed': base64.b64encode(master_seed).decode(),
            'signature_count': 0,
            'tree_height': self.tree_height,
            'ots_w': self.ots_w,
            'version': 2
        }
        
        public_key = {
            'root': base64.b64encode(root).decode(),
            'tree_height': self.tree_height,
            'ots_w': self.ots_w,
            'version': 2
        }
        
        return (base64.b64encode(json.dumps(public_key).encode()),
                base64.b64encode(json.dumps(private_key).encode()))
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        sk_data = json.loads(base64.b64decode(private_key))
        
        if sk_data['signature_count'] >= self.max_signatures:
            raise ValueError("Signature limit exceeded")
        
        idx = sk_data['signature_count']
        master_seed = base64.b64decode(sk_data['master_seed'])
        
        leaf_seed = hashlib.sha3_512(master_seed + struct.pack('>Q', idx)).digest()
        sk_ots = self._ots_keygen(leaf_seed)
        
        message_hash = hashlib.sha3_512(message + struct.pack('>Q', idx)).digest()
        ots_signature = self._ots_sign(message_hash, sk_ots)
        
        auth_path = self._compute_auth_path(master_seed, idx)
        
        signature = {
            'index': idx,
            'ots_signature': [base64.b64encode(s).decode() for s in ots_signature],
            'auth_path': [base64.b64encode(p).decode() for p in auth_path],
            'version': 2
        }
        
        sk_data['signature_count'] += 1
        
        return base64.b64encode(json.dumps(signature).encode())
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            sig_data = json.loads(base64.b64decode(signature))
            pk_data = json.loads(base64.b64decode(public_key))
            
            idx = sig_data['index']
            ots_signature = [base64.b64decode(s) for s in sig_data['ots_signature']]
            auth_path = [base64.b64decode(p) for p in sig_data['auth_path']]
            root = base64.b64decode(pk_data['root'])
            
            message_hash = hashlib.sha3_512(message + struct.pack('>Q', idx)).digest()
            
            if not self._ots_verify(message_hash, ots_signature):
                return False
            
            pk_ots = self._ots_recover_public_key(message_hash, ots_signature)
            leaf_hash = hashlib.sha3_256(pk_ots).digest()
            
            computed_root = self._verify_merkle_path(leaf_hash, idx, auth_path)
            
            return ConstantTimeOps.ct_compare_bytes(computed_root, root)
            
        except Exception:
            return False
    
    def _ots_keygen(self, seed: bytes) -> List[bytes]:
        key_parts = []
        l1 = 256 // 4 if self.ots_w == 16 else 256 // 8
        l2 = 3 if self.ots_w == 16 else 2
        l = l1 + l2
        
        for i in range(l):
            part_seed = hashlib.sha3_256(seed + struct.pack('>H', i)).digest()
            key_parts.append(part_seed)
        
        return key_parts
    
    def _ots_derive_public_key(self, private_key: List[bytes]) -> bytes:
        public_parts = []
        
        for sk_part in private_key:
            pk_part = sk_part
            for _ in range(self.ots_w - 1):
                pk_part = hashlib.sha3_256(pk_part).digest()
            public_parts.append(pk_part)
        
        return b''.join(public_parts)
    
    def _ots_sign(self, message: bytes, private_key: List[bytes]) -> List[bytes]:
        signature_parts = []
        
        l1 = 256 // 4 if self.ots_w == 16 else 256 // 8
        l2 = 3 if self.ots_w == 16 else 2
        
        checksum = 0
        message_blocks = []
        
        if self.ots_w == 16:
            for i in range(0, 256, 4):
                byte_idx = i // 8
                bit_offset = i % 8
                if byte_idx < len(message):
                    nibble = (message[byte_idx] >> (bit_offset // 2 * 4)) & 0xF
                else:
                    nibble = 0
                message_blocks.append(nibble)
                checksum += 15 - nibble
        else:
            for byte in message:
                message_blocks.extend([(byte >> 4) & 0xF, byte & 0xF])
                checksum += (15 - ((byte >> 4) & 0xF)) + (15 - (byte & 0xF))
        
        checksum_bytes = checksum.to_bytes(2, 'big')
        for byte in checksum_bytes:
            if self.ots_w == 16:
                message_blocks.extend([(byte >> 4) & 0xF, byte & 0xF])
            else:
                message_blocks.append(byte)
        
        for i, (block, sk_part) in enumerate(zip(message_blocks, private_key)):
            sig_part = sk_part
            for _ in range(block):
                sig_part = hashlib.sha3_256(sig_part).digest()
            signature_parts.append(sig_part)
        
        return signature_parts
    
    def _ots_verify(self, message: bytes, signature: List[bytes]) -> bool:
        try:
            pk_recovered = self._ots_recover_public_key(message, signature)
            return len(pk_recovered) > 0
        except:
            return False
    
    def _ots_recover_public_key(self, message: bytes, signature: List[bytes]) -> bytes:
        public_parts = []
        
        l1 = 256 // 4 if self.ots_w == 16 else 256 // 8
        l2 = 3 if self.ots_w == 16 else 2
        
        checksum = 0
        message_blocks = []
        
        if self.ots_w == 16:
            for i in range(0, 256, 4):
                byte_idx = i // 8
                bit_offset = i % 8
                if byte_idx < len(message):
                    nibble = (message[byte_idx] >> (bit_offset // 2 * 4)) & 0xF
                else:
                    nibble = 0
                message_blocks.append(nibble)
                checksum += 15 - nibble
        else:
            for byte in message:
                message_blocks.extend([(byte >> 4) & 0xF, byte & 0xF])
                checksum += (15 - ((byte >> 4) & 0xF)) + (15 - (byte & 0xF))
        
        checksum_bytes = checksum.to_bytes(2, 'big')
        for byte in checksum_bytes:
            if self.ots_w == 16:
                message_blocks.extend([(byte >> 4) & 0xF, byte & 0xF])
            else:
                message_blocks.append(byte)
        
        for i, (block, sig_part) in enumerate(zip(message_blocks, signature)):
            pk_part = sig_part
            for _ in range(self.ots_w - 1 - block):
                pk_part = hashlib.sha3_256(pk_part).digest()
            public_parts.append(pk_part)
        
        return b''.join(public_parts)
    
    def _build_merkle_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        tree = [leaves]
        
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = hashlib.sha3_256(left + right).digest()
                next_level.append(parent)
            tree.insert(0, next_level)
            current_level = next_level
        
        return tree
    
    def _compute_auth_path(self, master_seed: bytes, leaf_index: int) -> List[bytes]:
        leaves = []
        for i in range(self.max_signatures):
            leaf_seed = hashlib.sha3_512(master_seed + struct.pack('>Q', i)).digest()
            sk_ots = self._ots_keygen(leaf_seed)
            pk_ots = self._ots_derive_public_key(sk_ots)
            leaves.append(hashlib.sha3_256(pk_ots).digest())
        
        tree = self._build_merkle_tree(leaves)
        
        auth_path = []
        idx = leaf_index
        
        for level in range(len(tree) - 1, 0, -1):
            sibling_idx = idx ^ 1
            if sibling_idx < len(tree[level]):
                auth_path.append(tree[level][sibling_idx])
            else:
                auth_path.append(tree[level][idx])
            idx >>= 1
        
        return auth_path
    
    def _verify_merkle_path(self, leaf: bytes, index: int, auth_path: List[bytes]) -> bytes:
        current = leaf
        idx = index
        
        for sibling in auth_path:
            if idx & 1:
                current = hashlib.sha3_256(sibling + current).digest()
            else:
                current = hashlib.sha3_256(current + sibling).digest()
            idx >>= 1
        
        return current

class LatticeKeySwitching:
    def __init__(self, params: CryptoParameters):
        self.params = params
        self.rng = SecureRNG()
        self.gaussian = DiscreteGaussian(params.gaussian_parameter)
    
    def generate_switching_key(self, secret_old: np.ndarray, secret_new: np.ndarray) -> Dict[str, Any]:
        dimension = len(secret_old)
        
        A = np.array([[self.rng.get_uniform_int(self.params.lattice_modulus) 
                      for _ in range(dimension)] 
                     for _ in range(dimension)], dtype=np.int64)
        
        E = self.gaussian.sample_vector(dimension)
        
        B = (A @ secret_new + E + secret_old) % self.params.lattice_modulus
        
        return {
            'A': A.tolist(),
            'B': B.tolist(),
            'dimension': dimension
        }
    
    def key_switch(self, ciphertext: Tuple[np.ndarray, np.ndarray], 
                   switching_key: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray]:
        c0, c1 = ciphertext
        A = np.array(switching_key['A'], dtype=np.int64)
        B = np.array(switching_key['B'], dtype=np.int64)
        
        c0_new = c0.copy()
        c1_new = (A @ c1 + B) % self.params.lattice_modulus
        
        return c0_new, c1_new

class BootstrappingEngine:
    def __init__(self, params: CryptoParameters):
        self.params = params
        self.rng = SecureRNG()
        self.gaussian = DiscreteGaussian(params.gaussian_parameter)
        self.key_switcher = LatticeKeySwitching(params)
    
    def generate_bootstrapping_key(self, secret_key: np.ndarray) -> Dict[str, Any]:
        dimension = len(secret_key)
        
        rlwe_samples = []
        for i in range(dimension):
            a = self.rng.get_uniform_int(self.params.lattice_modulus)
            e = self.gaussian.sample()
            b = (a * secret_key[i] + e) % self.params.lattice_modulus
            rlwe_samples.append((a, b))
        
        return {
            'rlwe_samples': rlwe_samples,
            'dimension': dimension
        }
    
    def bootstrap(self, ciphertext: Tuple[np.ndarray, np.ndarray], 
                  bootstrapping_key: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray]:
        c0, c1 = ciphertext
        rlwe_samples = bootstrapping_key['rlwe_samples']
        
        noise_estimate = np.sum(np.abs(c0)) + np.sum(np.abs(c1))
        
        if noise_estimate < self.params.noise_bound:
            return c0, c1
        
        refreshed_c0 = np.zeros_like(c0)
        refreshed_c1 = np.zeros_like(c1)
        
        for i, (a, b) in enumerate(rlwe_samples):
            if i < len(c1):
                mask = c1[i] & 1
                refreshed_c0[i] = (mask * a) % self.params.lattice_modulus
                refreshed_c1[i] = (mask * b) % self.params.lattice_modulus
        
        fresh_noise = self.gaussian.sample_vector(len(c0))
        refreshed_c0 = (refreshed_c0 + fresh_noise) % self.params.lattice_modulus
        
        return refreshed_c0, refreshed_c1

class QRCs:
    def __init__(self, security_level: SecurityLevel = SecurityLevel.QUANTUM_256):
        self.security_level = security_level
        self.params = self._initialize_parameters(security_level)
        self.rng = SecureRNG()
        self.gaussian = DiscreteGaussian(self.params.gaussian_parameter)
        self.ecc = AdvancedErrorCorrection(255, 223, 16)
        self.signature_engine = HybridSignature(self.params.hash_tree_height, self.params.ots_winternitz_w)
        self.key_switcher = LatticeKeySwitching(self.params)
        self.bootstrapper = BootstrappingEngine(self.params)
        self._session_keys = {}
        self._lock = threading.Lock()
    
    def _initialize_parameters(self, level: SecurityLevel) -> CryptoParameters:
        params_table = {
            SecurityLevel.CLASSICAL_128: CryptoParameters(
                ring_dimension=1024, coefficient_modulus=[40961, 40993], plaintext_modulus=1024,
                noise_bound=3.2, security_margin=1.5,
                lattice_dimension=512, lattice_modulus=12289, gaussian_parameter=3.2, rejection_bound=5,
                code_length=255, code_dimension=223, minimum_distance=33,
                hash_tree_height=16, ots_winternitz_w=16, ots_key_size=32,
                multivariate_variables=80, multivariate_equations=80, field_size=256,
                isogeny_prime=431, isogeny_degree=216, supersingular_count=72,
                entropy_pool_size=4096, rng_reseed_interval=3600, side_channel_protection=1
            ),
            SecurityLevel.QUANTUM_256: CryptoParameters(
                ring_dimension=2048, coefficient_modulus=[120833, 120853, 120871], plaintext_modulus=4096,
                noise_bound=6.4, security_margin=2.0,
                lattice_dimension=1024, lattice_modulus=40961, gaussian_parameter=4.5, rejection_bound=8,
                code_length=511, code_dimension=447, minimum_distance=65,
                hash_tree_height=24, ots_winternitz_w=32, ots_key_size=64,
                multivariate_variables=128, multivariate_equations=128, field_size=256,
                isogeny_prime=1021, isogeny_degree=512, supersingular_count=171,
                entropy_pool_size=8192, rng_reseed_interval=1800, side_channel_protection=2
            ),
            SecurityLevel.FORTRESS: CryptoParameters(
                ring_dimension=4096, coefficient_modulus=[1073479681, 1073479693, 1073479711, 1073479729], 
                plaintext_modulus=8192, noise_bound=12.8, security_margin=3.0,
                lattice_dimension=2048, lattice_modulus=120833, gaussian_parameter=6.0, rejection_bound=12,
                code_length=1023, code_dimension=895, minimum_distance=129,
                hash_tree_height=32, ots_winternitz_w=256, ots_key_size=128,
                multivariate_variables=256, multivariate_equations=256, field_size=65536,
                isogeny_prime=2203, isogeny_degree=1024, supersingular_count=367,
                entropy_pool_size=16384, rng_reseed_interval=900, side_channel_protection=3
            )
        }
        
        if level not in params_table:
            level = SecurityLevel.QUANTUM_256
        
        return params_table[level]
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        with self._lock:
            master_seed = self.rng.get_bytes(128)
            key_id = self.rng.get_bytes(32)
            
            ring_a = RingPolynomial(
                np.array([self.rng.get_uniform_int(self.params.coefficient_modulus[0]) 
                         for _ in range(self.params.ring_dimension)], dtype=np.int64),
                self.params.coefficient_modulus[0]
            )
            
            lattice_A = np.array([[self.rng.get_uniform_int(self.params.lattice_modulus) 
                                  for _ in range(self.params.lattice_dimension)] 
                                 for _ in range(self.params.lattice_dimension)], dtype=np.int64)
            
            secret_poly = RingPolynomial(
                self.gaussian.sample_vector(self.params.ring_dimension),
                self.params.coefficient_modulus[0]
            )
            
            secret_vector = self.gaussian.sample_vector(self.params.lattice_dimension)
            
            error_poly = RingPolynomial(
                self.gaussian.sample_vector(self.params.ring_dimension),
                self.params.coefficient_modulus[0]
            )
            
            error_vector = self.gaussian.sample_vector(self.params.lattice_dimension)
            
            public_poly = ring_a * secret_poly + error_poly
            public_vector = (lattice_A @ secret_vector + error_vector) % self.params.lattice_modulus
            
            signature_pk, signature_sk = self.signature_engine.keygen()
            
            switching_key = self.key_switcher.generate_switching_key(secret_vector, secret_vector)
            bootstrapping_key = self.bootstrapper.generate_bootstrapping_key(secret_vector)
            
            private_key_data = {
                'master_seed': base64.b64encode(master_seed).decode(),
                'key_id': base64.b64encode(key_id).decode(),
                'secret_poly': secret_poly.to_bytes(),
                'secret_vector': secret_vector.tolist(),
                'signature_sk': signature_sk.decode(),
                'switching_key': switching_key,
                'bootstrapping_key': bootstrapping_key,
                'security_level': self.security_level.value,
                'creation_time': int(time.time_ns()),
                'version': 3
            }
            
            public_key_data = {
                'key_id': base64.b64encode(key_id).decode(),
                'ring_a': ring_a.to_bytes(),
                'public_poly': public_poly.to_bytes(),
                'lattice_A': lattice_A.tolist(),
                'public_vector': public_vector.tolist(),
                'signature_pk': signature_pk.decode(),
                'parameters': {
                    'ring_dimension': self.params.ring_dimension,
                    'coefficient_modulus': self.params.coefficient_modulus,
                    'lattice_dimension': self.params.lattice_dimension,
                    'lattice_modulus': self.params.lattice_modulus,
                    'security_level': self.security_level.value
                },
                'version': 3
            }
            
            sk_compressed = zlib.compress(json.dumps(private_key_data).encode(), level=9)
            pk_compressed = zlib.compress(json.dumps(public_key_data).encode(), level=9)
            
            return (base64.b64encode(pk_compressed), base64.b64encode(sk_compressed))
    
    def encrypt(self, plaintext: bytes, public_key: bytes, associated_data: bytes = b'') -> bytes:
        pk_data = json.loads(zlib.decompress(base64.b64decode(public_key)))
        
        ring_a = RingPolynomial.from_bytes(pk_data['ring_a'], self.params.coefficient_modulus[0])
        public_poly = RingPolynomial.from_bytes(pk_data['public_poly'], self.params.coefficient_modulus[0])
        lattice_A = np.array(pk_data['lattice_A'], dtype=np.int64)
        public_vector = np.array(pk_data['public_vector'], dtype=np.int64)
        
        session_nonce = self.rng.get_bytes(32)
        timestamp = int(time.time_ns())
        
        plaintext_compressed = zlib.compress(plaintext, level=9)
        plaintext_padded = self._pad_message(plaintext_compressed)
        
        ephemeral_r = RingPolynomial(
            self.gaussian.sample_vector(self.params.ring_dimension),
            self.params.coefficient_modulus[0]
        )
        
        ephemeral_e1 = RingPolynomial(
            self.gaussian.sample_vector(self.params.ring_dimension),
            self.params.coefficient_modulus[0]
        )
        
        ephemeral_e2 = RingPolynomial(
            self.gaussian.sample_vector(self.params.ring_dimension),
            self.params.coefficient_modulus[0]
        )
        
        lattice_r = self.gaussian.sample_vector(self.params.lattice_dimension)
        lattice_e1 = self.gaussian.sample_vector(self.params.lattice_dimension)
        lattice_e2 = self.gaussian.sample_vector(self.params.lattice_dimension)
        
        ciphertext_blocks = []
        
        for block_idx in range(0, len(plaintext_padded), self.params.ring_dimension // 8):
            block_data = plaintext_padded[block_idx:block_idx + self.params.ring_dimension // 8]
            
            message_poly = self._encode_to_polynomial(block_data)
            
            hybrid_entropy = self._generate_hybrid_entropy(session_nonce, timestamp, block_idx, associated_data)
            
            u_ring = ring_a * ephemeral_r + ephemeral_e1
            v_ring = public_poly * ephemeral_r + ephemeral_e2 + message_poly.scalar_mul(self.params.coefficient_modulus[0] // 2)
            
            u_lattice = (lattice_A.T @ lattice_r + lattice_e1) % self.params.lattice_modulus
            v_lattice = (public_vector @ lattice_r + lattice_e2) % self.params.lattice_modulus
            
            u_ring_bytes = u_ring.to_bytes()
            v_ring_bytes = v_ring.to_bytes()
            u_lattice_bytes = u_lattice.tobytes()
            v_lattice_bytes = v_lattice.tobytes()
            
            u_ring_ecc = self.ecc.encode(u_ring_bytes[:self.ecc.k])
            v_ring_ecc = self.ecc.encode(v_ring_bytes[:self.ecc.k])
            u_lattice_ecc = self.ecc.encode(u_lattice_bytes[:self.ecc.k])
            v_lattice_ecc = self.ecc.encode(v_lattice_bytes[:self.ecc.k])
            
            block_hmac = hmac.new(hybrid_entropy, 
                                  u_ring_ecc + v_ring_ecc + u_lattice_ecc + v_lattice_ecc,
                                  hashlib.sha3_512).digest()
            
            ciphertext_blocks.append({
                'u_ring': base64.b64encode(u_ring_ecc).decode(),
                'v_ring': base64.b64encode(v_ring_ecc).decode(),
                'u_lattice': base64.b64encode(u_lattice_ecc).decode(),
                'v_lattice': base64.b64encode(v_lattice_ecc).decode(),
                'hmac': base64.b64encode(block_hmac).decode(),
                'block_index': block_idx
            })
        
        ciphertext_data = {
            'blocks': ciphertext_blocks,
            'session_nonce': base64.b64encode(session_nonce).decode(),
            'timestamp': timestamp,
            'key_id': pk_data['key_id'],
            'associated_data_hash': hashlib.sha3_256(associated_data).hexdigest(),
            'algorithm': f'QRCs-{self.security_level.name}',
            'version': 3
        }
        
        ciphertext_compressed = zlib.compress(json.dumps(ciphertext_data).encode(), level=9)
        return base64.b64encode(ciphertext_compressed)
    
    def decrypt(self, ciphertext: bytes, private_key: bytes, associated_data: bytes = b'') -> bytes:
        ct_data = json.loads(zlib.decompress(base64.b64decode(ciphertext)))
        sk_data = json.loads(zlib.decompress(base64.b64decode(private_key)))
        
        if ct_data['key_id'] != sk_data['key_id']:
            raise ValueError("Key ID mismatch")
        
        if ct_data['associated_data_hash'] != hashlib.sha3_256(associated_data).hexdigest():
            raise ValueError("Associated data mismatch")
        
        secret_poly = RingPolynomial.from_bytes(sk_data['secret_poly'], self.params.coefficient_modulus[0])
        secret_vector = np.array(sk_data['secret_vector'], dtype=np.int64)
        
        session_nonce = base64.b64decode(ct_data['session_nonce'])
        timestamp = ct_data['timestamp']
        
        decrypted_blocks = []
        
        for block in ct_data['blocks']:
            u_ring_ecc = base64.b64decode(block['u_ring'])
            v_ring_ecc = base64.b64decode(block['v_ring'])
            u_lattice_ecc = base64.b64decode(block['u_lattice'])
            v_lattice_ecc = base64.b64decode(block['v_lattice'])
            block_hmac = base64.b64decode(block['hmac'])
            block_idx = block['block_index']
            
            hybrid_entropy = self._generate_hybrid_entropy(session_nonce, timestamp, block_idx, associated_data)
            
            expected_hmac = hmac.new(hybrid_entropy, 
                                     u_ring_ecc + v_ring_ecc + u_lattice_ecc + v_lattice_ecc,
                                     hashlib.sha3_512).digest()
            
            if not ConstantTimeOps.ct_compare_bytes(block_hmac, expected_hmac):
                raise ValueError("HMAC verification failed")
            
            u_ring_bytes = self.ecc.decode(u_ring_ecc)
            v_ring_bytes = self.ecc.decode(v_ring_ecc)
            u_lattice_bytes = self.ecc.decode(u_lattice_ecc)
            v_lattice_bytes = self.ecc.decode(v_lattice_ecc)
            
            if not all([u_ring_bytes, v_ring_bytes, u_lattice_bytes, v_lattice_bytes]):
                raise ValueError("Error correction failed")
            
            u_ring = RingPolynomial.from_bytes(u_ring_bytes, self.params.coefficient_modulus[0])
            v_ring = RingPolynomial.from_bytes(v_ring_bytes, self.params.coefficient_modulus[0])
            
            message_poly = v_ring - u_ring * secret_poly
            
            block_data = self._decode_from_polynomial(message_poly)
            decrypted_blocks.append(block_data)
        
        decrypted_padded = b''.join(decrypted_blocks)
        decrypted_unpadded = self._unpad_message(decrypted_padded)
        
        return zlib.decompress(decrypted_unpadded)
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        sk_data = json.loads(zlib.decompress(base64.b64decode(private_key)))
        signature_sk = base64.b64encode(sk_data['signature_sk'].encode())
        
        return self.signature_engine.sign(message, signature_sk)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        pk_data = json.loads(zlib.decompress(base64.b64decode(public_key)))
        signature_pk = base64.b64encode(pk_data['signature_pk'].encode())
        
        return self.signature_engine.verify(message, signature, signature_pk)
    
    def _encode_to_polynomial(self, data: bytes) -> RingPolynomial:
        coefficients = np.zeros(self.params.ring_dimension, dtype=np.int64)
        
        for i, byte in enumerate(data):
            for bit in range(8):
                coeff_idx = i * 8 + bit
                if coeff_idx < self.params.ring_dimension:
                    coefficients[coeff_idx] = (byte >> bit) & 1
        
        return RingPolynomial(coefficients, self.params.coefficient_modulus[0])
    
    def _decode_from_polynomial(self, poly: RingPolynomial) -> bytes:
        data = bytearray()
        
        for byte_idx in range(self.params.ring_dimension // 8):
            byte_val = 0
            for bit in range(8):
                coeff_idx = byte_idx * 8 + bit
                if coeff_idx < len(poly.coefficients):
                    coeff = poly.coefficients[coeff_idx]
                    if coeff > self.params.coefficient_modulus[0] // 2:
                        coeff = coeff - self.params.coefficient_modulus[0]
                    
                    bit_val = 1 if abs(coeff - self.params.coefficient_modulus[0] // 2) < abs(coeff) else 0
                    byte_val |= bit_val << bit
            
            data.append(byte_val)
        
        return bytes(data)
    
    def _generate_hybrid_entropy(self, nonce: bytes, timestamp: int, block_idx: int, associated_data: bytes) -> bytes:
        entropy_input = (nonce + 
                        struct.pack('>Q', timestamp) + 
                        struct.pack('>Q', block_idx) + 
                        associated_data)
        
        base_entropy = hashlib.sha3_512(entropy_input).digest()
        
        extended_entropy = bytearray()
        for round_idx in range(8):
            round_input = base_entropy + struct.pack('>Q', round_idx)
            extended_entropy.extend(hashlib.blake2b(round_input, digest_size=64).digest())
        
        final_entropy = hashlib.sha3_512(bytes(extended_entropy)).digest()
        
        return final_entropy
    
    def _pad_message(self, data: bytes) -> bytes:
        block_size = self.params.ring_dimension // 8
        pad_length = block_size - (len(data) % block_size)
        
        padding = self.rng.get_bytes(pad_length - 1) + bytes([pad_length])
        return data + padding
    
    def _unpad_message(self, data: bytes) -> bytes:
        if not data:
            raise ValueError("Empty data")
        
        pad_length = data[-1]
        if pad_length > len(data) or pad_length == 0:
            raise ValueError("Invalid padding")
        
        return data[:-pad_length]

def save_key(key_data: bytes, filename: str):
    with open(filename, 'wb') as f:
        f.write(key_data)

def load_key(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()

def encrypt_file(public_key_file: str, input_file: str, output_file: str, security_level: SecurityLevel):
    system = QRCs(security_level)
    
    public_key = load_key(public_key_file)
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = system.encrypt(plaintext, public_key)
    
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(private_key_file: str, input_file: str, output_file: str, security_level: SecurityLevel):
    system = QRCs(security_level)
    
    private_key = load_key(private_key_file)
    
    with open(input_file, 'rb') as f:
        ciphertext = f.read()
    
    plaintext = system.decrypt(ciphertext, private_key)
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)

def run_test():
    system = QRCs(SecurityLevel.FORTRESS)
    
    public_key, private_key = system.generate_keypair()
    
    message = b"Quantum-Resistant Cryptographic System: Security for the post-quantum era with hybrid lattice-based encryption and hash-based signatures."
    associated_data = b"Authentication context"
    
    encrypted = system.encrypt(message, public_key, associated_data)
    decrypted = system.decrypt(encrypted, private_key, associated_data)
    
    signature = system.sign(message, private_key)
    is_valid = system.verify(message, signature, public_key)
    
    print("=== QRCs Test Results ===")
    print(f"Original message length: {len(message)} bytes")
    print(f"Encrypted data length: {len(encrypted)} bytes")
    print(f"Decryption successful: {message == decrypted}")
    print(f"Signature verification: {is_valid}")
    print(f"Security level: {system.security_level.name}")
    print(f"Ring dimension: {system.params.ring_dimension}")
    print(f"Lattice dimension: {system.params.lattice_dimension}")

def main():
    parser = argparse.ArgumentParser(
        prog='crypt.py',
        description='QRCs - Quantum-Resistant Cryptographic System'
    )
    
    parser.add_argument('command', nargs='?', choices=['keygen', 'encrypt', 'decrypt', 'test'],
                       help='Operation to perform')
    parser.add_argument('-s', '--security', choices=['classical_128', 'classical_192', 'classical_256', 
                                                     'quantum_128', 'quantum_192', 'quantum_256', 'fortress'],
                       default='quantum_256', help='Security level')
    parser.add_argument('-f', '--file', help='Input file path')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-k', '--key', help='Key file path')
    parser.add_argument('--public-key', help='Public key file path')
    parser.add_argument('--private-key', help='Private key file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    security_map = {
        'classical_128': SecurityLevel.CLASSICAL_128,
        'classical_192': SecurityLevel.CLASSICAL_192,
        'classical_256': SecurityLevel.CLASSICAL_256,
        'quantum_128': SecurityLevel.QUANTUM_128,
        'quantum_192': SecurityLevel.QUANTUM_192,
        'quantum_256': SecurityLevel.QUANTUM_256,
        'fortress': SecurityLevel.FORTRESS
    }
    security_level = security_map[args.security]
    
    try:
        if args.command == 'keygen':
            if not args.output:
                parser.error("keygen requires -o (base filename for keys)")
            
            print(f"Generating {args.security} security level keypair...")
            system = QRCs(security_level)
            public_key, private_key = system.generate_keypair()
            
            pub_filename = f"{args.output}.pub"
            priv_filename = f"{args.output}.priv"
            
            save_key(public_key, pub_filename)
            save_key(private_key, priv_filename)
            
            print(f"Public key saved to: {pub_filename}")
            print(f"Private key saved to: {priv_filename}")
            
        elif args.command == 'encrypt':
            if not all([args.file, args.output, args.public_key]):
                parser.error("encrypt requires -f, -o, and --public-key")
            
            print("Encrypting file...")
            encrypt_file(args.public_key, args.file, args.output, security_level)
            print(f"File encrypted and saved to: {args.output}")
            
        elif args.command == 'decrypt':
            if not all([args.file, args.output, args.private_key]):
                parser.error("decrypt requires -f, -o, and --private-key")
            
            print("Decrypting file...")
            decrypt_file(args.private_key, args.file, args.output, security_level)
            print(f"File decrypted and saved to: {args.output}")
            
        elif args.command == 'test':
            print("Running QRCs test suite...")
            run_test()
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
