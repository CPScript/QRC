import hashlib
import secrets
import numpy as np
from typing import Tuple, Dict, List, Optional, Union
import struct
import json
import time
import hmac
from dataclasses import dataclass
from enum import IntEnum
import base64
import zlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import ctypes
import sys

class SecurityLevel(IntEnum):
    LEVEL_128 = 128
    LEVEL_192 = 192
    LEVEL_256 = 256
    LEVEL_384 = 384
    LEVEL_512 = 512

@dataclass
class AQSParameters:
    n: int
    q: int
    sigma: float
    k: int
    l: int
    eta: int
    gamma: int
    omega: int
    salt_dimensions: int
    salt_size: int
    tree_height: int
    winternitz_w: int
    error_correction_t: int
    polynomial_degree: int

class ConstantTime:
    @staticmethod
    def select(a: int, b: int, choice: int) -> int:
        mask = -choice
        return (a & ~mask) | (b & mask)
    
    @staticmethod
    def compare(a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    @staticmethod
    def conditional_swap(a: int, b: int, swap: int) -> Tuple[int, int]:
        mask = -swap
        temp = mask & (a ^ b)
        return a ^ temp, b ^ temp

class GaussianSampler:
    def __init__(self, sigma: float, precision: int = 128):
        self.sigma = sigma
        self.precision = precision
        self.precomputed_table = self._build_cdf_table()
        
    def _build_cdf_table(self) -> List[Tuple[int, float]]:
        table = []
        bound = int(6 * self.sigma)
        normalization = 0.0
        
        for z in range(-bound, bound + 1):
            prob = np.exp(-z**2 / (2 * self.sigma**2))
            normalization += prob
            
        cumulative = 0.0
        for z in range(-bound, bound + 1):
            prob = np.exp(-z**2 / (2 * self.sigma**2)) / normalization
            cumulative += prob
            table.append((z, cumulative))
            
        return table
    
    def sample(self) -> int:
        u = secrets.SystemRandom().random()
        for z, cdf in self.precomputed_table:
            if u <= cdf:
                return z
        return self.precomputed_table[-1][0]
    
    def sample_vector(self, size: int) -> np.ndarray:
        return np.array([self.sample() for _ in range(size)], dtype=np.int64)

class Polynomial:
    def __init__(self, coeffs: Union[List[int], np.ndarray], modulus: int):
        self.coeffs = np.array(coeffs, dtype=np.int64) % modulus
        self.modulus = modulus
        self.degree = len(coeffs) - 1
        
    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        max_len = max(len(self.coeffs), len(other.coeffs))
        result = np.zeros(max_len, dtype=np.int64)
        result[:len(self.coeffs)] = self.coeffs
        result[:len(other.coeffs)] = (result[:len(other.coeffs)] + other.coeffs) % self.modulus
        return Polynomial(result, self.modulus)
    
    def __mul__(self, other: Union['Polynomial', int]) -> 'Polynomial':
        if isinstance(other, int):
            return Polynomial((self.coeffs * other) % self.modulus, self.modulus)
        
        result = np.zeros(len(self.coeffs) + len(other.coeffs) - 1, dtype=np.int64)
        for i, a in enumerate(self.coeffs):
            for j, b in enumerate(other.coeffs):
                result[i + j] = (result[i + j] + a * b) % self.modulus
        return Polynomial(result, self.modulus)
    
    def mod_reduce(self, poly_mod: 'Polynomial') -> 'Polynomial':
        dividend = self.coeffs.copy()
        divisor = poly_mod.coeffs
        
        while len(dividend) >= len(divisor):
            coeff = dividend[-1] * pow(int(divisor[-1]), -1, self.modulus) % self.modulus
            for i in range(len(divisor)):
                dividend[len(dividend) - len(divisor) + i] = (dividend[len(dividend) - len(divisor) + i] - coeff * divisor[i]) % self.modulus
            dividend = dividend[:-1]
            
        return Polynomial(dividend, self.modulus)
    
    def to_ntt(self) -> np.ndarray:
        n = len(self.coeffs)
        if n & (n - 1) != 0:
            raise ValueError("Polynomial degree must be power of 2 for NTT")
        
        omega = self._find_primitive_root(n)
        result = self.coeffs.copy()
        
        levels = int(np.log2(n))
        for level in range(levels):
            m = 1 << (levels - level)
            omega_m = pow(omega, n // m, self.modulus)
            
            for j in range(0, n, m):
                omega_power = 1
                for k in range(m // 2):
                    t = (omega_power * result[j + k + m // 2]) % self.modulus
                    u = result[j + k]
                    result[j + k] = (u + t) % self.modulus
                    result[j + k + m // 2] = (u - t) % self.modulus
                    omega_power = (omega_power * omega_m) % self.modulus
                    
        return result
    
    def from_ntt(self, ntt_coeffs: np.ndarray) -> 'Polynomial':
        n = len(ntt_coeffs)
        omega = self._find_primitive_root(n)
        omega_inv = pow(omega, -1, self.modulus)
        n_inv = pow(n, -1, self.modulus)
        
        result = ntt_coeffs.copy()
        
        levels = int(np.log2(n))
        for level in range(levels):
            m = 1 << (level + 1)
            omega_m = pow(omega_inv, n // m, self.modulus)
            
            for j in range(0, n, m):
                omega_power = 1
                for k in range(m // 2):
                    t = result[j + k + m // 2]
                    u = result[j + k]
                    result[j + k] = (u + t) % self.modulus
                    result[j + k + m // 2] = ((u - t) * omega_power) % self.modulus
                    omega_power = (omega_power * omega_m) % self.modulus
                    
        result = (result * n_inv) % self.modulus
        return Polynomial(result, self.modulus)
    
    def _find_primitive_root(self, n: int) -> int:
        factors = []
        temp = self.modulus - 1
        for p in [2, 3, 5, 7, 11, 13]:
            while temp % p == 0:
                factors.append(p)
                temp //= p
        if temp > 1:
            factors.append(temp)
            
        for g in range(2, self.modulus):
            is_primitive = True
            for factor in set(factors):
                if pow(g, (self.modulus - 1) // factor, self.modulus) == 1:
                    is_primitive = False
                    break
            if is_primitive:
                return pow(g, (self.modulus - 1) // n, self.modulus)
        
        raise ValueError("No primitive root found")

class ReedSolomonECC:
    def __init__(self, n: int, k: int, field_size: int):
        self.n = n
        self.k = k
        self.field_size = field_size
        self.generator_poly = self._build_generator()
        
    def _build_generator(self) -> List[int]:
        g = [1]
        for i in range(self.n - self.k):
            g = self._poly_mult(g, [1, pow(2, i, self.field_size)])
        return g
    
    def _poly_mult(self, p1: List[int], p2: List[int]) -> List[int]:
        result = [0] * (len(p1) + len(p2) - 1)
        for i, a in enumerate(p1):
            for j, b in enumerate(p2):
                result[i + j] ^= self._gf_mult(a, b)
        return result
    
    def _gf_mult(self, a: int, b: int) -> int:
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a & self.field_size:
                a ^= self.field_size + 1
            b >>= 1
        return result & (self.field_size - 1)
    
    def encode(self, data: bytes) -> bytes:
        if len(data) > self.k:
            raise ValueError("Data too large for encoding")
        
        padded = data + bytes(self.k - len(data))
        data_poly = list(padded)
        
        remainder = [0] * (self.n - self.k)
        for i in range(self.k):
            coeff = data_poly[i] ^ remainder[0]
            if coeff != 0:
                for j in range(1, len(self.generator_poly)):
                    remainder[j - 1] = remainder[j] ^ self._gf_mult(self.generator_poly[j], coeff)
            else:
                remainder = remainder[1:] + [0]
                
        return padded + bytes(remainder)
    
    def decode(self, encoded: bytes) -> Optional[bytes]:
        syndromes = []
        for i in range(self.n - self.k):
            s = 0
            for j in range(self.n):
                s ^= self._gf_mult(encoded[j], pow(pow(2, i, self.field_size), j, self.field_size))
            syndromes.append(s)
            
        if all(s == 0 for s in syndromes):
            return encoded[:self.k]
        
        error_locator = self._berlekamp_massey(syndromes)
        error_positions = self._find_error_positions(error_locator)
        
        if error_positions:
            corrected = bytearray(encoded)
            for pos in error_positions:
                corrected[pos] ^= self._calculate_error_magnitude(pos, syndromes, error_positions)
            return bytes(corrected[:self.k])
        
        return None
    
    def _berlekamp_massey(self, syndromes: List[int]) -> List[int]:
        n = len(syndromes)
        s = syndromes
        c = [1]
        b = [1]
        l = 0
        m = 1
        
        for i in range(n):
            d = s[i]
            for j in range(1, l + 1):
                if j <= len(c) - 1:
                    d ^= self._gf_mult(c[j], s[i - j])
                    
            if d == 0:
                m += 1
            else:
                t = c[:]
                c = self._poly_add(c, self._poly_scale(b, d))
                
                if 2 * l <= i:
                    l = i + 1 - l
                    b = self._poly_scale(t, pow(d, -1, self.field_size))
                    m = 1
                else:
                    m += 1
                    
        return c
    
    def _poly_add(self, a: List[int], b: List[int]) -> List[int]:
        result = a[:] if len(a) > len(b) else b[:]
        shorter = b if len(a) > len(b) else a
        for i in range(len(shorter)):
            result[i] ^= shorter[i]
        return result
    
    def _poly_scale(self, poly: List[int], scalar: int) -> List[int]:
        return [self._gf_mult(coeff, scalar) for coeff in poly]
    
    def _find_error_positions(self, error_locator: List[int]) -> List[int]:
        positions = []
        for i in range(self.n):
            result = 0
            for j, coeff in enumerate(error_locator):
                result ^= self._gf_mult(coeff, pow(pow(2, i, self.field_size), j, self.field_size))
            if result == 0:
                positions.append(i)
        return positions
    
    def _calculate_error_magnitude(self, position: int, syndromes: List[int], error_positions: List[int]) -> int:
        numerator = 0
        denominator = 1
        
        for i, s in enumerate(syndromes):
            term = s
            for pos in error_positions:
                if pos != position:
                    term = self._gf_mult(term, 1 ^ self._gf_mult(pow(2, pos, self.field_size), pow(2, i, self.field_size)))
            numerator ^= term
            
        for pos in error_positions:
            if pos != position:
                denominator = self._gf_mult(denominator, pow(2, position, self.field_size) ^ pow(2, pos, self.field_size))
                
        return self._gf_mult(numerator, pow(denominator, -1, self.field_size))

class MerkleTree:
    def __init__(self, height: int, seed: bytes):
        self.height = height
        self.seed = seed
        self.nodes = {}
        self.wots = WinternitzOTS()
        self._build_tree()
        
    def _build_tree(self):
        executor = ThreadPoolExecutor(max_workers=os.cpu_count())
        futures = []
        
        for i in range(2**self.height):
            future = executor.submit(self._compute_leaf, i)
            futures.append((i, future))
            
        for i, future in futures:
            self.nodes[(self.height, i)] = future.result()
            
        for level in range(self.height - 1, -1, -1):
            for i in range(2**level):
                left = self.nodes[(level + 1, 2 * i)]
                right = self.nodes[(level + 1, 2 * i + 1)]
                self.nodes[(level, i)] = hashlib.sha3_256(left + right).digest()
                
        executor.shutdown()
    
    def _compute_leaf(self, index: int) -> bytes:
        leaf_seed = hashlib.sha3_512(self.seed + struct.pack('>Q', index)).digest()
        sk_wots = self.wots.keygen(leaf_seed)
        pk_wots = self.wots.derive_public_key(sk_wots)
        return hashlib.sha3_256(pk_wots).digest()
    
    def get_root(self) -> bytes:
        return self.nodes[(0, 0)]
    
    def get_auth_path(self, leaf_index: int) -> List[bytes]:
        path = []
        index = leaf_index
        
        for level in range(self.height):
            sibling_index = index ^ 1
            path.append(self.nodes[(self.height - level, sibling_index)])
            index //= 2
            
        return path
    
    def get_leaf_secret(self, index: int) -> bytes:
        return hashlib.sha3_512(self.seed + struct.pack('>Q', index)).digest()

class WinternitzOTS:
    def __init__(self, w: int = 16, hash_size: int = 32):
        self.w = w
        self.hash_size = hash_size
        self.l1 = (8 * hash_size + int(np.log2(w)) - 1) // int(np.log2(w))
        self.l2 = int(np.log2(self.l1 * (w - 1)) / np.log2(w)) + 1
        self.l = self.l1 + self.l2
        
    def keygen(self, seed: bytes) -> List[bytes]:
        sk = []
        for i in range(self.l):
            sk.append(hashlib.sha3_256(seed + struct.pack('>H', i)).digest())
        return sk
    
    def derive_public_key(self, sk: List[bytes]) -> bytes:
        pk = []
        for i, s in enumerate(sk):
            chain = s
            for _ in range(self.w - 1):
                chain = hashlib.sha3_256(chain).digest()
            pk.append(chain)
        return b''.join(pk)
    
    def sign(self, message: bytes, sk: List[bytes]) -> List[bytes]:
        msg_hash = hashlib.sha3_256(message).digest()
        checksum = 0
        msg_blocks = []
        
        bits_per_block = int(np.log2(self.w))
        mask = (1 << bits_per_block) - 1
        
        for i in range(self.l1):
            offset = i * bits_per_block
            byte_offset = offset // 8
            bit_offset = offset % 8
            
            if byte_offset < len(msg_hash):
                value = msg_hash[byte_offset]
                if byte_offset + 1 < len(msg_hash) and bit_offset + bits_per_block > 8:
                    value |= msg_hash[byte_offset + 1] << 8
                block = (value >> bit_offset) & mask
            else:
                block = 0
                
            msg_blocks.append(block)
            checksum += self.w - 1 - block
            
        checksum_bytes = checksum.to_bytes((self.l2 * bits_per_block + 7) // 8, 'big')
        for i in range(self.l2):
            offset = i * bits_per_block
            byte_offset = offset // 8
            bit_offset = offset % 8
            
            if byte_offset < len(checksum_bytes):
                value = checksum_bytes[byte_offset]
                if byte_offset + 1 < len(checksum_bytes) and bit_offset + bits_per_block > 8:
                    value |= checksum_bytes[byte_offset + 1] << 8
                block = (value >> bit_offset) & mask
            else:
                block = 0
                
            msg_blocks.append(block)
            
        signature = []
        for i, (block, s) in enumerate(zip(msg_blocks, sk)):
            chain = s
            for _ in range(block):
                chain = hashlib.sha3_256(chain).digest()
            signature.append(chain)
            
        return signature
    
    def verify(self, message: bytes, signature: List[bytes], pk: bytes) -> bool:
        if len(signature) != self.l:
            return False
            
        msg_hash = hashlib.sha3_256(message).digest()
        checksum = 0
        msg_blocks = []
        
        bits_per_block = int(np.log2(self.w))
        mask = (1 << bits_per_block) - 1
        
        for i in range(self.l1):
            offset = i * bits_per_block
            byte_offset = offset // 8
            bit_offset = offset % 8
            
            if byte_offset < len(msg_hash):
                value = msg_hash[byte_offset]
                if byte_offset + 1 < len(msg_hash) and bit_offset + bits_per_block > 8:
                    value |= msg_hash[byte_offset + 1] << 8
                block = (value >> bit_offset) & mask
            else:
                block = 0
                
            msg_blocks.append(block)
            checksum += self.w - 1 - block
            
        checksum_bytes = checksum.to_bytes((self.l2 * bits_per_block + 7) // 8, 'big')
        for i in range(self.l2):
            offset = i * bits_per_block
            byte_offset = offset // 8
            bit_offset = offset % 8
            
            if byte_offset < len(checksum_bytes):
                value = checksum_bytes[byte_offset]
                if byte_offset + 1 < len(checksum_bytes) and bit_offset + bits_per_block > 8:
                    value |= checksum_bytes[byte_offset + 1] << 8
                block = (value >> bit_offset) & mask
            else:
                block = 0
                
            msg_blocks.append(block)
            
        pk_computed = []
        for i, (block, sig) in enumerate(zip(msg_blocks, signature)):
            chain = sig
            for _ in range(self.w - 1 - block):
                chain = hashlib.sha3_256(chain).digest()
            pk_computed.append(chain)
            
        return b''.join(pk_computed) == pk

class LatticeOperations:
    @staticmethod
    def gram_schmidt(basis: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        n = basis.shape[0]
        orthogonal = np.zeros_like(basis, dtype=np.float64)
        mu = np.zeros((n, n), dtype=np.float64)
        
        for i in range(n):
            orthogonal[i] = basis[i].astype(np.float64)
            for j in range(i):
                mu[i, j] = np.dot(basis[i], orthogonal[j]) / np.dot(orthogonal[j], orthogonal[j])
                orthogonal[i] -= mu[i, j] * orthogonal[j]
                
        return orthogonal, mu
    
    @staticmethod
    def babai_nearest_plane(target: np.ndarray, basis: np.ndarray) -> np.ndarray:
        orthogonal, mu = LatticeOperations.gram_schmidt(basis)
        n = basis.shape[0]
        coeffs = np.zeros(n)
        
        for i in range(n - 1, -1, -1):
            coeffs[i] = np.dot(target, orthogonal[i]) / np.dot(orthogonal[i], orthogonal[i])
            target = target - round(coeffs[i]) * basis[i]
            
        return np.round(coeffs).astype(np.int64)
    
    @staticmethod
    def reduce_basis(basis: np.ndarray, delta: float = 0.75) -> np.ndarray:
        n = basis.shape[0]
        b = basis.copy()
        
        orthogonal, mu = LatticeOperations.gram_schmidt(b)
        
        k = 1
        while k < n:
            for j in range(k - 1, -1, -1):
                if abs(mu[k, j]) > 0.5:
                    b[k] = b[k] - round(mu[k, j]) * b[j]
                    orthogonal, mu = LatticeOperations.gram_schmidt(b)
                    
            if np.dot(orthogonal[k], orthogonal[k]) >= (delta - mu[k, k-1]**2) * np.dot(orthogonal[k-1], orthogonal[k-1]):
                k += 1
            else:
                b[[k, k-1]] = b[[k-1, k]]
                orthogonal, mu = LatticeOperations.gram_schmidt(b)
                k = max(k - 1, 1)
                
        return b

class AQS:
    def __init__(self, security_level: SecurityLevel = SecurityLevel.LEVEL_256):
        self.params = self._get_parameters(security_level)
        self.gaussian_sampler = GaussianSampler(self.params.sigma)
        self.ecc = ReedSolomonECC(255, 223, 256)
        self._lock = threading.Lock()
        
    def _get_parameters(self, level: SecurityLevel) -> AQSParameters:
        params_map = {
            SecurityLevel.LEVEL_128: AQSParameters(
                n=512, q=12289, sigma=3.2, k=2, l=2, eta=2, gamma=1, omega=80,
                salt_dimensions=3, salt_size=32, tree_height=16, winternitz_w=16,
                error_correction_t=16, polynomial_degree=512
            ),
            SecurityLevel.LEVEL_192: AQSParameters(
                n=768, q=18433, sigma=4.0, k=3, l=3, eta=2, gamma=1, omega=96,
                salt_dimensions=4, salt_size=48, tree_height=20, winternitz_w=16,
                error_correction_t=24, polynomial_degree=768
            ),
            SecurityLevel.LEVEL_256: AQSParameters(
                n=1024, q=40961, sigma=4.5, k=4, l=4, eta=2, gamma=1, omega=128,
                salt_dimensions=4, salt_size=64, tree_height=24, winternitz_w=16,
                error_correction_t=32, polynomial_degree=1024
            ),
            SecurityLevel.LEVEL_384: AQSParameters(
                n=1536, q=61441, sigma=5.0, k=5, l=5, eta=3, gamma=2, omega=192,
                salt_dimensions=5, salt_size=96, tree_height=28, winternitz_w=32,
                error_correction_t=48, polynomial_degree=1536
            ),
            SecurityLevel.LEVEL_512: AQSParameters(
                n=2048, q=120833, sigma=6.0, k=6, l=6, eta=3, gamma=2, omega=256,
                salt_dimensions=6, salt_size=128, tree_height=32, winternitz_w=32,
                error_correction_t=64, polynomial_degree=2048
            )
        }
        return params_map[level]
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        with self._lock:
            A = np.random.randint(0, self.params.q, size=(self.params.n, self.params.n), dtype=np.int64)
            
            s1 = self.gaussian_sampler.sample_vector(self.params.n)
            s2 = self.gaussian_sampler.sample_vector(self.params.n)
            
            e1 = self.gaussian_sampler.sample_vector(self.params.n)
            e2 = self.gaussian_sampler.sample_vector(self.params.n)
            
            t = (np.dot(A, s1) + s2) % self.params.q
            
            merkle_seed = secrets.token_bytes(64)
            merkle_tree = MerkleTree(self.params.tree_height, merkle_seed)
            merkle_root = merkle_tree.get_root()
            
            polynomial_irred = self._generate_irreducible_polynomial()
            
            private_key_data = {
                's1': s1.tolist(),
                's2': s2.tolist(),
                'e1': e1.tolist(),
                'e2': e2.tolist(),
                'merkle_seed': base64.b64encode(merkle_seed).decode('ascii'),
                'signature_counter': 0,
                'polynomial_irred': polynomial_irred.tolist(),
                'key_id': base64.b64encode(secrets.token_bytes(16)).decode('ascii'),
                'creation_time': int(time.time()),
                'salt_history': [],
                'version': 1
            }
            
            public_key_data = {
                'A': A.tolist(),
                't': t.tolist(),
                'merkle_root': base64.b64encode(merkle_root).decode('ascii'),
                'params': {
                    'n': self.params.n,
                    'q': self.params.q,
                    'sigma': self.params.sigma,
                    'k': self.params.k,
                    'l': self.params.l
                },
                'polynomial_irred': polynomial_irred.tolist(),
                'key_id': base64.b64encode(secrets.token_bytes(16)).decode('ascii'),
                'version': 1
            }
            
            private_key = base64.b64encode(
                zlib.compress(json.dumps(private_key_data).encode('utf-8'), level=9)
            )
            
            public_key = base64.b64encode(
                zlib.compress(json.dumps(public_key_data).encode('utf-8'), level=9)
            )
            
            return public_key, private_key
    
    def encrypt(self, message: bytes, public_key: bytes) -> bytes:
        pk_data = json.loads(zlib.decompress(base64.b64decode(public_key)))
        
        A = np.array(pk_data['A'], dtype=np.int64)
        t = np.array(pk_data['t'], dtype=np.int64)
        poly_irred = Polynomial(pk_data['polynomial_irred'], self.params.q)
        
        salts = self._generate_quantum_salts()
        timestamp = int(time.time() * 1000000)
        nonce = secrets.token_bytes(32)
        
        message_compressed = zlib.compress(message, level=9)
        padded_msg = self._quantum_pad(message_compressed)
        
        blocks = []
        for i in range(0, len(padded_msg), self.params.n // 8):
            block = padded_msg[i:i + self.params.n // 8]
            
            msg_poly = self._encode_message_to_polynomial(block)
            
            r = np.array([secrets.randbelow(self.params.eta * 2 + 1) - self.params.eta 
                         for _ in range(self.params.n)], dtype=np.int64)
            
            e1 = self.gaussian_sampler.sample_vector(self.params.n)
            e2 = self.gaussian_sampler.sample_vector(self.params.n)
            e3 = self.gaussian_sampler.sample_vector(self.params.n)
            
            salt_matrix = self._compute_salt_matrix(salts, timestamp, i)
            
            u = (np.dot(A.T, r) + e1) % self.params.q
            v = (np.dot(t, r) + e2 + (self.params.q // 2) * msg_poly.coeffs[:self.params.n]) % self.params.q
            
            u_salted = (u + np.dot(salt_matrix, e3)) % self.params.q
            
            error_corrected_u = self.ecc.encode(u_salted.tobytes())
            error_corrected_v = self.ecc.encode(v.tobytes())
            
            blocks.append({
                'u': base64.b64encode(error_corrected_u).decode('ascii'),
                'v': base64.b64encode(error_corrected_v).decode('ascii')
            })
        
        ciphertext = {
            'blocks': blocks,
            'salts': [base64.b64encode(s).decode('ascii') for s in salts],
            'timestamp': timestamp,
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'key_id': pk_data['key_id'],
            'algorithm': f'AQS-{self.params.n}',
            'version': 1
        }
        
        return base64.b64encode(
            zlib.compress(json.dumps(ciphertext).encode('utf-8'), level=9)
        )
    
    def decrypt(self, ciphertext: bytes, private_key: bytes) -> bytes:
        ct_data = json.loads(zlib.decompress(base64.b64decode(ciphertext)))
        sk_data = json.loads(zlib.decompress(base64.b64decode(private_key)))
        
        s1 = np.array(sk_data['s1'], dtype=np.int64)
        s2 = np.array(sk_data['s2'], dtype=np.int64)
        
        salts = [base64.b64decode(s) for s in ct_data['salts']]
        timestamp = ct_data['timestamp']
        
        decrypted_blocks = []
        
        for i, block_data in enumerate(ct_data['blocks']):
            u_encoded = base64.b64decode(block_data['u'])
            v_encoded = base64.b64decode(block_data['v'])
            
            u_decoded = self.ecc.decode(u_encoded)
            v_decoded = self.ecc.decode(v_encoded)
            
            if u_decoded is None or v_decoded is None:
                raise ValueError("Error correction failed")
            
            u = np.frombuffer(u_decoded, dtype=np.int64)[:self.params.n]
            v = np.frombuffer(v_decoded, dtype=np.int64)[:self.params.n]
            
            salt_matrix = self._compute_salt_matrix(salts, timestamp, i)
            
            w = (v - np.dot(s1, u) - np.dot(s2, np.ones(self.params.n, dtype=np.int64))) % self.params.q
            
            msg_poly = self._decode_polynomial_to_message(w)
            decrypted_blocks.append(msg_poly)
        
        decrypted = b''.join(decrypted_blocks)
        unpadded = self._quantum_unpad(decrypted)
        
        return zlib.decompress(unpadded)
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        sk_data = json.loads(zlib.decompress(base64.b64decode(private_key)))
        
        if sk_data['signature_counter'] >= 2**self.params.tree_height:
            raise ValueError("Signature limit reached")
        
        merkle_seed = base64.b64decode(sk_data['merkle_seed'])
        sig_index = sk_data['signature_counter']
        
        merkle_tree = MerkleTree(self.params.tree_height, merkle_seed)
        auth_path = merkle_tree.get_auth_path(sig_index)
        
        leaf_seed = merkle_tree.get_leaf_secret(sig_index)
        wots = WinternitzOTS(self.params.winternitz_w)
        sk_wots = wots.keygen(leaf_seed)
        
        msg_hash = hashlib.sha3_512(message).digest()
        salt = secrets.token_bytes(64)
        
        salted_hash = hashlib.sha3_512(msg_hash + salt + struct.pack('>Q', sig_index)).digest()
        
        ots_signature = wots.sign(salted_hash, sk_wots)
        
        sk_data['signature_counter'] = sig_index + 1
        
        signature_data = {
            'ots_signature': [base64.b64encode(s).decode('ascii') for s in ots_signature],
            'salt': base64.b64encode(salt).decode('ascii'),
            'index': sig_index,
            'auth_path': [base64.b64encode(p).decode('ascii') for p in auth_path],
            'timestamp': int(time.time() * 1000000),
            'key_id': sk_data['key_id'],
            'algorithm': f'AQS-WOTS-{self.params.winternitz_w}',
            'version': 1
        }
        
        updated_sk = base64.b64encode(
            zlib.compress(json.dumps(sk_data).encode('utf-8'), level=9)
        )
        
        signature = base64.b64encode(
            zlib.compress(json.dumps(signature_data).encode('utf-8'), level=9)
        )
        
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            sig_data = json.loads(zlib.decompress(base64.b64decode(signature)))
            pk_data = json.loads(zlib.decompress(base64.b64decode(public_key)))
            
            ots_signature = [base64.b64decode(s) for s in sig_data['ots_signature']]
            salt = base64.b64decode(sig_data['salt'])
            sig_index = sig_data['index']
            auth_path = [base64.b64decode(p) for p in sig_data['auth_path']]
            merkle_root = base64.b64decode(pk_data['merkle_root'])
            
            msg_hash = hashlib.sha3_512(message).digest()
            salted_hash = hashlib.sha3_512(msg_hash + salt + struct.pack('>Q', sig_index)).digest()
            
            wots = WinternitzOTS(self.params.winternitz_w)
            
            pk_computed = []
            for sig_part in ots_signature:
                chain = sig_part
                for _ in range(self.params.winternitz_w - 1):
                    chain = hashlib.sha3_256(chain).digest()
                pk_computed.append(chain)
            
            leaf_hash = hashlib.sha3_256(b''.join(pk_computed)).digest()
            
            current_hash = leaf_hash
            index = sig_index
            
            for sibling in auth_path:
                if index & 1:
                    current_hash = hashlib.sha3_256(sibling + current_hash).digest()
                else:
                    current_hash = hashlib.sha3_256(current_hash + sibling).digest()
                index >>= 1
            
            return ConstantTime.compare(current_hash, merkle_root)
            
        except Exception:
            return False
    
    def _generate_irreducible_polynomial(self) -> np.ndarray:
        while True:
            coeffs = np.random.randint(0, self.params.q, size=self.params.n + 1, dtype=np.int64)
            coeffs[0] = 1
            coeffs[-1] = 1
            
            poly = Polynomial(coeffs, self.params.q)
            
            if self._is_irreducible(poly):
                return coeffs
    
    def _is_irreducible(self, poly: Polynomial) -> bool:
        x = Polynomial([0, 1], self.params.q)
        x_power = x
        
        for i in range(1, poly.degree // 2 + 1):
            x_power = (x_power * x_power).mod_reduce(poly)
            gcd = self._polynomial_gcd(poly, x_power + Polynomial([-1], self.params.q))
            if len(gcd.coeffs) > 1:
                return False
                
        return True
    
    def _polynomial_gcd(self, a: Polynomial, b: Polynomial) -> Polynomial:
        while len(b.coeffs) > 0 and any(c != 0 for c in b.coeffs):
            a, b = b, a.mod_reduce(b)
        return a
    
    def _generate_quantum_salts(self) -> List[bytes]:
        salts = []
        
        for dim in range(self.params.salt_dimensions):
            base_salt = secrets.token_bytes(self.params.salt_size)
            
            if dim == 0:
                salt = hashlib.sha3_512(base_salt).digest()[:self.params.salt_size]
            elif dim == 1:
                salt = hashlib.blake2b(base_salt, digest_size=self.params.salt_size).digest()
            elif dim == 2:
                h1 = hashlib.sha3_256(base_salt).digest()
                h2 = hashlib.sha3_384(base_salt + h1).digest()
                salt = hashlib.sha3_512(h1 + h2).digest()[:self.params.salt_size]
            elif dim == 3:
                rounds = 5
                salt = base_salt
                for _ in range(rounds):
                    salt = hashlib.sha3_512(salt + base_salt).digest()[:self.params.salt_size]
            else:
                quantum_state = self._quantum_hash_function(base_salt, dim)
                salt = quantum_state[:self.params.salt_size]
                
            salts.append(salt)
            
        return salts
    
    def _quantum_hash_function(self, data: bytes, rounds: int) -> bytes:
        state = bytearray(256)
        data_expanded = hashlib.sha3_512(data).digest() * 4
        
        for i in range(256):
            state[i] = data_expanded[i]
            
        for round_num in range(rounds):
            for i in range(256):
                j = (i + state[i] + round_num) % 256
                state[i], state[j] = state[j], state[i]
                
            temp = hashlib.sha3_512(bytes(state)).digest()
            for i in range(64):
                state[i * 4:(i + 1) * 4] = struct.pack('>I', 
                    struct.unpack('>I', temp[i*4:(i+1)*4])[0] ^ 
                    struct.unpack('>I', state[i*4:(i+1)*4])[0]
                )
                
        return hashlib.sha3_512(bytes(state)).digest()
    
    def _compute_salt_matrix(self, salts: List[bytes], timestamp: int, block_index: int) -> np.ndarray:
        combined = b''.join(salts)
        time_bytes = struct.pack('>Q', timestamp // 1000000)
        block_bytes = struct.pack('>I', block_index)
        
        seed = hashlib.sha3_512(combined + time_bytes + block_bytes).digest()
        
        matrix = np.zeros((self.params.n, self.params.n), dtype=np.int64)
        
        for i in range(self.params.n):
            row_seed = hashlib.sha3_256(seed + struct.pack('>I', i)).digest()
            for j in range(self.params.n):
                byte_index = (j * 2) % len(row_seed)
                matrix[i, j] = struct.unpack('>H', row_seed[byte_index:byte_index + 2])[0] % self.params.q
                
        return matrix
    
    def _encode_message_to_polynomial(self, message: bytes) -> Polynomial:
        coeffs = np.zeros(self.params.n, dtype=np.int64)
        
        for i, byte in enumerate(message):
            if i * 8 >= self.params.n:
                break
            for bit in range(8):
                if i * 8 + bit < self.params.n:
                    coeffs[i * 8 + bit] = (byte >> bit) & 1
                    
        return Polynomial(coeffs, self.params.q)
    
    def _decode_polynomial_to_message(self, poly_coeffs: np.ndarray) -> bytes:
        message = bytearray()
        
        for i in range(0, len(poly_coeffs), 8):
            byte = 0
            for bit in range(8):
                if i + bit < len(poly_coeffs):
                    coeff = poly_coeffs[i + bit]
                    if coeff > self.params.q // 2:
                        coeff = coeff - self.params.q
                        
                    bit_value = 1 if abs(coeff - self.params.q // 2) < abs(coeff) else 0
                    byte |= bit_value << bit
                    
            message.append(byte)
            
        return bytes(message)
    
    def _quantum_pad(self, data: bytes) -> bytes:
        block_size = self.params.n // 8
        pad_len = block_size - (len(data) % block_size)
        
        quantum_noise = secrets.token_bytes(pad_len - 1)
        padding = quantum_noise + bytes([pad_len])
        
        return data + padding
    
    def _quantum_unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]

if __name__ == "__main__":
    aqs = AQS(SecurityLevel.LEVEL_256)
    
    public_key, private_key = aqs.generate_keypair()
    
    message = b"QRC: Post-quantum cryptography for the quantum era"
    
    encrypted = aqs.encrypt(message, public_key)
    decrypted = aqs.decrypt(encrypted, private_key)
    
    signature = aqs.sign(message, private_key)
    is_valid = aqs.verify(message, signature, public_key)
    
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {message == decrypted}")
    print(f"Signature valid: {is_valid}")
