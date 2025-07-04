#!/usr/bin/env python3

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
    NIST_1 = 128
    NIST_3 = 192  
    NIST_5 = 256

@dataclass
class CryptoParameters:
    n: int
    q: int
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    noise_bound: float
    
    xmss_height: int
    wots_w: int
    wots_len: int
    
    poly_bytes: int
    secret_key_bytes: int
    public_key_bytes: int
    ciphertext_bytes: int

class ConstantTime:
    @staticmethod
    def select_u32(a: int, b: int, c: int) -> int:
        mask = (-c) & 0xFFFFFFFF
        return (a & mask) | (b & (~mask))
    
    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        d = 0
        for x, y in zip(a, b):
            d |= x ^ y
        return d == 0
    
    @staticmethod
    def cmov(r: bytearray, x: bytes, b: int):
        mask = -b & 0xFF
        for i in range(len(r)):
            if i < len(x):
                r[i] ^= mask & (r[i] ^ x[i])

class SHAKE256:
    def __init__(self):
        self.state = [0] * 25
        self.pos = 0
        self.rate = 136
    
    def absorb(self, data: bytes):
        for byte in data:
            if self.pos >= self.rate:
                self._keccak_f()
                self.pos = 0
            self.state[self.pos // 8] ^= byte << (8 * (self.pos % 8))
            self.pos += 1
    
    def finalize(self):
        if self.pos < self.rate:
            self.state[self.pos // 8] ^= 0x1F << (8 * (self.pos % 8))
        self.state[(self.rate - 1) // 8] ^= 0x80 << (8 * ((self.rate - 1) % 8))
        self._keccak_f()
        self.pos = 0
    
    def squeeze(self, length: int) -> bytes:
        output = bytearray()
        while len(output) < length:
            if self.pos >= self.rate:
                self._keccak_f()
                self.pos = 0
            
            remaining = min(length - len(output), self.rate - self.pos)
            for i in range(remaining):
                byte_idx = (self.pos + i) // 8
                bit_offset = ((self.pos + i) % 8) * 8
                if byte_idx < len(self.state):
                    output.append((self.state[byte_idx] >> bit_offset) & 0xFF)
                else:
                    output.append(0)
            
            self.pos += remaining
        
        return bytes(output)
    
    def _keccak_f(self):
        RC = [0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09,
              0x8a, 0x88, 0x09, 0x03, 0x8b, 0x8b, 0x8b, 0x89,
              0x03, 0x02, 0x80, 0x00, 0x0a, 0x0a, 0x81, 0x8a]
        
        for round_idx in range(24):
            C = [self.state[i] ^ self.state[i+5] ^ self.state[i+10] ^ self.state[i+15] ^ self.state[i+20] for i in range(5)]
            D = [C[(i+4)%5] ^ self._rotl64(C[(i+1)%5], 1) for i in range(5)]
            
            for i in range(25):
                self.state[i] ^= D[i % 5]
            
            B = [0] * 25
            B[0] = self.state[0]
            for i in range(1, 25):
                j = (i * 6) % 25
                rho = ((i-1) * i) // 2
                B[j] = self._rotl64(self.state[i], rho % 64)
            
            for i in range(0, 25, 5):
                for j in range(5):
                    self.state[i+j] = B[i+j] ^ ((~B[i+(j+1)%5]) & B[i+(j+2)%5])
            
            self.state[0] ^= RC[round_idx]
    
    def _rotl64(self, x: int, n: int) -> int:
        n = n % 64
        if n == 0:
            return x & 0xFFFFFFFFFFFFFFFF
        return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def shake256(data: bytes, length: int) -> bytes:
    shake = SHAKE256()
    shake.absorb(data)
    shake.finalize()
    return shake.squeeze(length)

class SecureRandom:
    def __init__(self):
        self._pool = bytearray(8192)
        self._idx = 0
        self._counter = 0
        self._last_reseed = time.time_ns()
        self._lock = threading.Lock()
        self._reseed()
    
    def _reseed(self):
        entropy = bytearray()
        entropy.extend(secrets.token_bytes(2048))
        entropy.extend(struct.pack('>Q', time.time_ns()))
        entropy.extend(struct.pack('>Q', os.getpid()))
        
        if hasattr(os, 'urandom'):
            entropy.extend(os.urandom(1024))
        
        try:
            with open('/dev/urandom', 'rb') as f:
                entropy.extend(f.read(512))
        except:
            pass
        
        if kernel32:
            try:
                buf = ctypes.create_string_buffer(256)
                kernel32.RtlGenRandom(buf, 256)
                entropy.extend(buf.raw)
            except:
                pass
        
        mixed = shake256(bytes(self._pool) + bytes(entropy), len(self._pool))
        for i in range(len(mixed)):
            self._pool[i] = mixed[i]
        
        self._idx = 0
        self._counter = 0
        self._last_reseed = time.time_ns()
    
    def bytes(self, length: int) -> bytes:
        with self._lock:
            if time.time_ns() - self._last_reseed > 300_000_000_000 or self._counter > 1000000:
                self._reseed()
            
            output = bytearray()
            while len(output) < length:
                if self._idx >= len(self._pool) - 64:
                    self._reseed()
                
                chunk_size = min(64, length - len(output))
                state = bytes(self._pool[self._idx:self._idx + 64])
                chunk = shake256(state + struct.pack('>Q', self._counter), chunk_size)
                output.extend(chunk)
                
                self._idx = (self._idx + 17) % (len(self._pool) - 64)
                self._counter += 1
            
            return bytes(output)
    
    def uniform_int(self, bound: int) -> int:
        if bound <= 1:
            return 0
        byte_length = (bound.bit_length() + 7) // 8
        while True:
            candidate = int.from_bytes(self.bytes(byte_length), 'little')
            if candidate < bound:
                return candidate

class GaussianSampler:
    def __init__(self, sigma: float, precision: int = 64):
        self.sigma = sigma
        self.precision = precision
        self.tail_bound = max(1, int(6 * sigma))
        self.rng = SecureRandom()
        self._build_cdt()
    
    def _build_cdt(self):
        self.cdt = []
        total = 0.0
        
        for z in range(-self.tail_bound, self.tail_bound + 1):
            prob = np.exp(-z * z / (2.0 * self.sigma * self.sigma))
            total += prob
            self.cdt.append((total, z))
        
        if total > 0:
            self.cdt = [(p / total, z) for p, z in self.cdt]
        else:
            self.cdt = [(1.0, 0)]
    
    def sample(self) -> int:
        u = int.from_bytes(self.rng.bytes(8), 'little') / (2**64)
        for prob, value in self.cdt:
            if u <= prob:
                return value
        return 0
    
    def sample_vector(self, length: int) -> np.ndarray:
        return np.array([self.sample() for _ in range(length)], dtype=np.int32)

class NTT:
    def __init__(self, n: int, q: int):
        self.n = n
        self.q = q
        self.ninv = pow(n, q - 2, q)
        self.root = self._find_primitive_root()
        self.zetas = self._compute_zetas()
        self.zetas_inv = [pow(z, q - 2, q) for z in self.zetas]
    
    def _find_primitive_root(self) -> int:
        for g in range(2, min(self.q, 1000)):
            if pow(g, self.n, self.q) == 1 and pow(g, self.n // 2, self.q) != 1:
                return g
        return 17
    
    def _compute_zetas(self) -> List[int]:
        zetas = []
        k = 1
        
        length = 2
        while length <= self.n:
            for start in range(0, self.n, 2 * length):
                zeta = pow(self.root, k * (self.q - 1) // self.n, self.q)
                zetas.append(zeta)
                k += 2
            length *= 2
        
        return zetas
    
    def forward(self, poly: np.ndarray) -> np.ndarray:
        a = poly.copy().astype(np.int64)
        k = 0
        
        length = 2
        while length <= self.n:
            for start in range(0, self.n, 2 * length):
                if k < len(self.zetas):
                    zeta = self.zetas[k]
                    k += 1
                else:
                    zeta = 1
                    
                for j in range(start, start + length):
                    if j + length < len(a):
                        t = (zeta * a[j + length]) % self.q
                        a[j + length] = (a[j] - t) % self.q
                        a[j] = (a[j] + t) % self.q
            length *= 2
        
        return a.astype(np.int32)
    
    def inverse(self, poly: np.ndarray) -> np.ndarray:
        a = poly.copy().astype(np.int64)
        k = len(self.zetas_inv) - 1
        
        length = self.n // 2
        while length >= 2:
            for start in range(0, self.n, 2 * length):
                if k >= 0 and k < len(self.zetas_inv):
                    zeta = self.zetas_inv[k]
                    k -= 1
                else:
                    zeta = 1
                    
                for j in range(start, start + length):
                    if j + length < len(a):
                        t = a[j]
                        a[j] = (t + a[j + length]) % self.q
                        a[j + length] = (zeta * (t - a[j + length])) % self.q
            length //= 2
        
        for i in range(len(a)):
            a[i] = (a[i] * self.ninv) % self.q
        
        return a.astype(np.int32)

class Polynomial:
    def __init__(self, coeffs: np.ndarray, q: int):
        self.coeffs = np.array(coeffs, dtype=np.int32) % q
        self.q = q
        self.n = len(coeffs)
        self.ntt = NTT(self.n, q) if self.n in [256, 512, 1024] and q > self.n else None
    
    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        return Polynomial((self.coeffs + other.coeffs) % self.q, self.q)
    
    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        return Polynomial((self.coeffs - other.coeffs) % self.q, self.q)
    
    def __mul__(self, other: 'Polynomial') -> 'Polynomial':
        if self.ntt and other.ntt and len(self.coeffs) == len(other.coeffs):
            try:
                a_ntt = self.ntt.forward(self.coeffs)
                b_ntt = self.ntt.forward(other.coeffs)
                c_ntt = (a_ntt * b_ntt) % self.q
                result = self.ntt.inverse(c_ntt)
                return Polynomial(result, self.q)
            except:
                pass
        
        result = np.zeros(self.n, dtype=np.int32)
        for i in range(self.n):
            for j in range(self.n):
                idx = i + j
                coeff_product = int(self.coeffs[i]) * int(other.coeffs[j])
                if idx >= self.n:
                    result[idx - self.n] = (result[idx - self.n] - coeff_product) % self.q
                else:
                    result[idx] = (result[idx] + coeff_product) % self.q
        
        return Polynomial(result, self.q)
    
    def compress(self, d: int) -> np.ndarray:
        if d <= 0 or d >= 32:
            return self.coeffs.copy()
        scale = 1 << d
        return np.array([((int(x) * scale + self.q // 2) // self.q) % scale for x in self.coeffs], dtype=np.int32)
    
    def decompress(self, compressed: np.ndarray, d: int) -> 'Polynomial':
        if d <= 0 or d >= 32:
            return Polynomial(compressed, self.q)
        scale = 1 << d
        coeffs = np.array([int(x) * self.q // scale for x in compressed], dtype=np.int32)
        return Polynomial(coeffs, self.q)
    
    def to_bytes(self) -> bytes:
        if self.q <= 1:
            return bytes(len(self.coeffs))
            
        bits_per_coeff = max(1, (self.q - 1).bit_length())
        total_bits = self.n * bits_per_coeff
        total_bytes = (total_bits + 7) // 8
        
        result = bytearray(total_bytes)
        bit_pos = 0
        
        for coeff in self.coeffs:
            coeff = int(coeff) % self.q
            for bit in range(bits_per_coeff):
                if bit >= 0 and coeff & (1 << bit):
                    byte_idx = bit_pos // 8
                    bit_idx = bit_pos % 8
                    if byte_idx < len(result) and bit_idx >= 0:
                        result[byte_idx] |= 1 << bit_idx
                bit_pos += 1
        
        return bytes(result)
    
    @classmethod
    def from_bytes(cls, data: bytes, n: int, q: int) -> 'Polynomial':
        if q <= 1:
            return cls(np.zeros(n, dtype=np.int32), max(q, 2))
            
        bits_per_coeff = max(1, (q - 1).bit_length())
        coeffs = np.zeros(n, dtype=np.int32)
        bit_pos = 0
        
        for i in range(n):
            coeff = 0
            for bit in range(bits_per_coeff):
                byte_idx = bit_pos // 8
                bit_idx = bit_pos % 8
                if (byte_idx < len(data) and bit_idx >= 0 and 
                    bit >= 0 and (data[byte_idx] & (1 << bit_idx))):
                    coeff |= 1 << bit
                bit_pos += 1
            coeffs[i] = coeff % q
        
        return cls(coeffs, q)

class PolynomialVector:
    def __init__(self, polys: List[Polynomial]):
        self.polys = polys
        self.k = len(polys)
        self.q = polys[0].q if polys else 2
        self.n = polys[0].n if polys else 0
    
    def __add__(self, other: 'PolynomialVector') -> 'PolynomialVector':
        return PolynomialVector([p1 + p2 for p1, p2 in zip(self.polys, other.polys)])
    
    def __sub__(self, other: 'PolynomialVector') -> 'PolynomialVector':
        return PolynomialVector([p1 - p2 for p1, p2 in zip(self.polys, other.polys)])
    
    def dot(self, other: 'PolynomialVector') -> Polynomial:
        if not self.polys or not other.polys:
            return Polynomial(np.zeros(self.n, dtype=np.int32), self.q)
            
        result = self.polys[0] * other.polys[0]
        for i in range(1, min(len(self.polys), len(other.polys))):
            result = result + (self.polys[i] * other.polys[i])
        return result
    
    def compress(self, d: int) -> List[np.ndarray]:
        return [poly.compress(d) for poly in self.polys]
    
    def decompress(self, compressed: List[np.ndarray], d: int) -> 'PolynomialVector':
        polys = []
        for comp in compressed:
            base_poly = Polynomial(np.zeros(self.n, dtype=np.int32), self.q)
            polys.append(base_poly.decompress(comp, d))
        return PolynomialVector(polys)
    
    def to_bytes(self) -> bytes:
        return b''.join(poly.to_bytes() for poly in self.polys)
    
    @classmethod
    def from_bytes(cls, data: bytes, k: int, n: int, q: int) -> 'PolynomialVector':
        base_poly = Polynomial(np.zeros(n, dtype=np.int32), q)
        poly_size = len(base_poly.to_bytes())
        polys = []
        
        for i in range(k):
            start = i * poly_size
            end = (i + 1) * poly_size
            if end <= len(data):
                poly_data = data[start:end]
            else:
                poly_data = data[start:] + b'\x00' * (end - len(data))
            polys.append(Polynomial.from_bytes(poly_data, n, q))
        
        return cls(polys)

class PolynomialMatrix:
    def __init__(self, matrix: List[List[Polynomial]]):
        self.matrix = matrix
        self.rows = len(matrix)
        self.cols = len(matrix[0]) if matrix else 0
        self.q = matrix[0][0].q if matrix and matrix[0] else 2
        self.n = matrix[0][0].n if matrix and matrix[0] else 0
    
    def multiply_vector(self, vec: PolynomialVector) -> PolynomialVector:
        result_polys = []
        for i in range(self.rows):
            if self.cols > 0 and len(vec.polys) > 0:
                poly_sum = self.matrix[i][0] * vec.polys[0]
                for j in range(1, min(self.cols, len(vec.polys))):
                    poly_sum = poly_sum + (self.matrix[i][j] * vec.polys[j])
                result_polys.append(poly_sum)
            else:
                result_polys.append(Polynomial(np.zeros(self.n, dtype=np.int32), self.q))
        return PolynomialVector(result_polys)
    
    def to_bytes(self) -> bytes:
        return b''.join(b''.join(poly.to_bytes() for poly in row) for row in self.matrix)
    
    @classmethod
    def from_bytes(cls, data: bytes, rows: int, cols: int, n: int, q: int) -> 'PolynomialMatrix':
        base_poly = Polynomial(np.zeros(n, dtype=np.int32), q)
        poly_size = len(base_poly.to_bytes())
        matrix = []
        idx = 0
        
        for i in range(rows):
            row = []
            for j in range(cols):
                start = idx * poly_size
                end = (idx + 1) * poly_size
                if end <= len(data):
                    poly_data = data[start:end]
                else:
                    poly_data = data[start:] + b'\x00' * (end - len(data))
                row.append(Polynomial.from_bytes(poly_data, n, q))
                idx += 1
            matrix.append(row)
        
        return cls(matrix)

class WOTS:
    def __init__(self, n: int, w: int):
        self.n = n
        self.w = max(2, w)
        self.log_w = max(1, (self.w - 1).bit_length())
        self.len1 = (8 * n + self.log_w - 1) // self.log_w
        self.len2 = max(1, (self.len1 * (self.w - 1)).bit_length() // self.log_w + 1)
        self.len = self.len1 + self.len2
        self.rng = SecureRandom()
    
    def base_w(self, msg: bytes, out_len: int) -> List[int]:
        result = []
        total = 0
        bits = 0
        
        for byte in msg:
            total = (total << 8) + byte
            bits += 8
            
            while bits >= self.log_w and len(result) < out_len:
                shift_amount = max(0, bits - self.log_w)
                if shift_amount < 64:
                    result.append((total >> shift_amount) & (self.w - 1))
                else:
                    result.append(0)
                bits -= self.log_w
        
        while len(result) < out_len:
            if bits >= self.log_w:
                shift_amount = max(0, bits - self.log_w)
                if shift_amount < 64:
                    result.append((total >> shift_amount) & (self.w - 1))
                else:
                    result.append(0)
            else:
                result.append(0)
            bits = max(0, bits - self.log_w)
        
        return result[:out_len]
    
    def chain(self, x: bytes, i: int, s: int, seed: bytes, addr: List[int]) -> bytes:
        if s == 0:
            return x
        
        tmp = x
        for j in range(i, i + s):
            addr_copy = addr.copy()
            if len(addr_copy) > 4:
                addr_copy[4] = j
            hash_input = seed + struct.pack('>32I', *(addr_copy + [0] * (32 - len(addr_copy)))[:32]) + tmp
            tmp = shake256(hash_input, self.n)
        
        return tmp
    
    def keygen(self, seed: bytes, addr: List[int]) -> Tuple[List[bytes], List[bytes]]:
        sk = []
        pk = []
        
        for i in range(self.len):
            addr_copy = addr.copy()
            if len(addr_copy) > 3:
                addr_copy[3] = i
            while len(addr_copy) < 32:
                addr_copy.append(0)
            
            sk_i = shake256(seed + struct.pack('>32I', *addr_copy[:32]), self.n)
            sk.append(sk_i)
            pk_i = self.chain(sk_i, 0, self.w - 1, seed, addr_copy)
            pk.append(pk_i)
        
        return sk, pk
    
    def sign(self, msg: bytes, sk: List[bytes], seed: bytes, addr: List[int]) -> List[bytes]:
        csum = 0
        msg_base_w = self.base_w(msg, self.len1)
        
        for i in range(self.len1):
            csum += self.w - 1 - msg_base_w[i]
        
        csum_bytes = csum.to_bytes(max(1, (self.len2 * self.log_w + 7) // 8), 'big')
        csum_base_w = self.base_w(csum_bytes, self.len2)
        
        sig = []
        for i in range(self.len1):
            addr_copy = addr.copy()
            if len(addr_copy) > 3:
                addr_copy[3] = i
            sig.append(self.chain(sk[i], 0, msg_base_w[i], seed, addr_copy))
        
        for i in range(self.len2):
            addr_copy = addr.copy()
            if len(addr_copy) > 3:
                addr_copy[3] = self.len1 + i
            sig.append(self.chain(sk[self.len1 + i], 0, csum_base_w[i], seed, addr_copy))
        
        return sig
    
    def verify(self, msg: bytes, sig: List[bytes], pk: List[bytes], seed: bytes, addr: List[int]) -> bool:
        try:
            csum = 0
            msg_base_w = self.base_w(msg, self.len1)
            
            for i in range(self.len1):
                csum += self.w - 1 - msg_base_w[i]
            
            csum_bytes = csum.to_bytes(max(1, (self.len2 * self.log_w + 7) // 8), 'big')
            csum_base_w = self.base_w(csum_bytes, self.len2)
            
            computed_pk = []
            for i in range(self.len1):
                if i < len(sig):
                    addr_copy = addr.copy()
                    if len(addr_copy) > 3:
                        addr_copy[3] = i
                    steps = self.w - 1 - msg_base_w[i]
                    computed_pk.append(self.chain(sig[i], msg_base_w[i], steps, seed, addr_copy))
                else:
                    computed_pk.append(b'')
            
            for i in range(self.len2):
                if self.len1 + i < len(sig):
                    addr_copy = addr.copy()
                    if len(addr_copy) > 3:
                        addr_copy[3] = self.len1 + i
                    steps = self.w - 1 - csum_base_w[i]
                    computed_pk.append(self.chain(sig[self.len1 + i], csum_base_w[i], steps, seed, addr_copy))
                else:
                    computed_pk.append(b'')
            
            return len(computed_pk) == len(pk) and all(ConstantTime.compare_bytes(a, b) for a, b in zip(computed_pk, pk))
        except:
            return False

class XMSS:
    def __init__(self, n: int, h: int, w: int):
        self.n = n
        self.h = max(1, min(h, 20))
        self.w = max(2, w)
        self.wots = WOTS(n, w)
        self.rng = SecureRandom()
    
    def keygen(self) -> Tuple[bytes, bytes]:
        seed = self.rng.bytes(self.n)
        sk_seed = self.rng.bytes(self.n)
        sk_prf = self.rng.bytes(self.n)
        pub_seed = self.rng.bytes(self.n)
        
        leaves = []
        max_leaves = min(1 << self.h, 1024)
        
        for i in range(max_leaves):
            addr = [i] + [0] * 31
            try:
                _, pk = self.wots.keygen(sk_seed, addr)
                leaf = shake256(pub_seed + b''.join(pk), self.n)
                leaves.append(leaf)
            except:
                leaves.append(shake256(pub_seed + struct.pack('>I', i), self.n))
        
        if len(leaves) == 0:
            leaves = [shake256(pub_seed, self.n)]
        
        tree = self._build_tree(leaves, pub_seed)
        root = tree[0] if tree else shake256(pub_seed, self.n)
        
        sk = {
            'sk_seed': base64.b64encode(sk_seed).decode(),
            'sk_prf': base64.b64encode(sk_prf).decode(),
            'pub_seed': base64.b64encode(pub_seed).decode(),
            'root': base64.b64encode(root).decode(),
            'idx': 0,
            'h': self.h,
            'w': self.w,
            'n': self.n,
            'max_signatures': max_leaves
        }
        
        pk = {
            'root': base64.b64encode(root).decode(),
            'pub_seed': base64.b64encode(pub_seed).decode(),
            'h': self.h,
            'w': self.w,
            'n': self.n
        }
        
        return (json.dumps(pk).encode(), json.dumps(sk).encode())
    
    def _build_tree(self, leaves: List[bytes], pub_seed: bytes) -> List[bytes]:
        if not leaves:
            return [shake256(pub_seed, self.n)]
            
        tree = [leaves]
        level = leaves
        
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                parent = shake256(pub_seed + left + right, self.n)
                next_level.append(parent)
            tree.insert(0, next_level)
            level = next_level
        
        return tree
    
    def sign(self, msg: bytes, sk: bytes) -> bytes:
        try:
            sk_data = json.loads(sk)
            
            max_sigs = sk_data.get('max_signatures', 1 << self.h)
            if sk_data['idx'] >= max_sigs:
                raise ValueError("Signature capacity exceeded")
            
            sk_seed = base64.b64decode(sk_data['sk_seed'])
            sk_prf = base64.b64decode(sk_data['sk_prf'])
            pub_seed = base64.b64decode(sk_data['pub_seed'])
            idx = sk_data['idx']
            
            r = shake256(sk_prf + msg + struct.pack('>Q', idx), self.n)
            msg_hash = shake256(r + msg, self.n)
            
            addr = [idx] + [0] * 31
            wots_sk, _ = self.wots.keygen(sk_seed, addr)
            wots_sig = self.wots.sign(msg_hash, wots_sk, pub_seed, addr)
            
            auth_path = self._compute_auth_path(idx, sk_seed, pub_seed, max_sigs)
            
            signature = {
                'idx': idx,
                'r': base64.b64encode(r).decode(),
                'wots_sig': [base64.b64encode(s).decode() for s in wots_sig],
                'auth_path': [base64.b64encode(p).decode() for p in auth_path]
            }
            
            sk_data['idx'] += 1
            
            return json.dumps(signature).encode()
        except Exception as e:
            raise ValueError(f"Signing failed: {e}")
    
    def _compute_auth_path(self, idx: int, sk_seed: bytes, pub_seed: bytes, max_leaves: int) -> List[bytes]:
        leaves = []
        for i in range(max_leaves):
            addr = [i] + [0] * 31
            try:
                _, pk = self.wots.keygen(sk_seed, addr)
                leaf = shake256(pub_seed + b''.join(pk), self.n)
                leaves.append(leaf)
            except:
                leaves.append(shake256(pub_seed + struct.pack('>I', i), self.n))
        
        if not leaves:
            return [shake256(pub_seed, self.n)]
        
        tree = self._build_tree(leaves, pub_seed)
        
        auth_path = []
        current_idx = idx
        
        for level in range(len(tree) - 1, 0, -1):
            sibling_idx = current_idx ^ 1
            if sibling_idx < len(tree[level]):
                auth_path.append(tree[level][sibling_idx])
            else:
                auth_path.append(tree[level][current_idx])
            current_idx >>= 1
        
        return auth_path
    
    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
        try:
            sig_data = json.loads(sig)
            pk_data = json.loads(pk)
            
            idx = sig_data['idx']
            r = base64.b64decode(sig_data['r'])
            wots_sig = [base64.b64decode(s) for s in sig_data['wots_sig']]
            auth_path = [base64.b64decode(p) for p in sig_data['auth_path']]
            
            root = base64.b64decode(pk_data['root'])
            pub_seed = base64.b64decode(pk_data['pub_seed'])
            
            msg_hash = shake256(r + msg, self.n)
            
            addr = [idx] + [0] * 31
            _, wots_pk = self.wots.keygen(shake256(pub_seed, self.n), addr)
            
            if not self.wots.verify(msg_hash, wots_sig, wots_pk, pub_seed, addr):
                return False
            
            leaf = shake256(pub_seed + b''.join(wots_pk), self.n)
            computed_root = self._verify_auth_path(leaf, idx, auth_path, pub_seed)
            
            return ConstantTime.compare_bytes(computed_root, root)
        except:
            return False
    
    def _verify_auth_path(self, leaf: bytes, idx: int, auth_path: List[bytes], pub_seed: bytes) -> bytes:
        current = leaf
        current_idx = idx
        
        for sibling in auth_path:
            if current_idx & 1:
                current = shake256(pub_seed + sibling + current, self.n)
            else:
                current = shake256(pub_seed + current + sibling, self.n)
            current_idx >>= 1
        
        return current

class KyberKEM:
    def __init__(self, security_level: SecurityLevel):
        self.security_level = security_level
        self.params = self._get_parameters(security_level)
        self.rng = SecureRandom()
        self.gaussian = GaussianSampler(self.params.eta1)
        self.xmss = XMSS(32, self.params.xmss_height, self.params.wots_w)
    
    def _get_parameters(self, level: SecurityLevel) -> CryptoParameters:
        if level == SecurityLevel.NIST_1:
            return CryptoParameters(
                n=256, q=3329, k=2, eta1=3, eta2=2, du=10, dv=4,
                noise_bound=6.0, xmss_height=10, wots_w=16, wots_len=67,
                poly_bytes=384, secret_key_bytes=1632, public_key_bytes=800,
                ciphertext_bytes=768
            )
        elif level == SecurityLevel.NIST_3:
            return CryptoParameters(
                n=256, q=3329, k=3, eta1=2, eta2=2, du=10, dv=4,
                noise_bound=4.0, xmss_height=12, wots_w=16, wots_len=67,
                poly_bytes=384, secret_key_bytes=2400, public_key_bytes=1184,
                ciphertext_bytes=1088
            )
        else:
            return CryptoParameters(
                n=256, q=3329, k=4, eta1=2, eta2=2, du=11, dv=5,
                noise_bound=4.0, xmss_height=14, wots_w=16, wots_len=67,
                poly_bytes=384, secret_key_bytes=3168, public_key_bytes=1568,
                ciphertext_bytes=1568
            )
    
    def _sample_polynomial(self, seed: bytes, nonce: int, eta: int) -> Polynomial:
        gaussian = GaussianSampler(eta)
        coeffs = gaussian.sample_vector(self.params.n)
        return Polynomial(coeffs, self.params.q)
    
    def _sample_matrix(self, seed: bytes, k: int) -> PolynomialMatrix:
        matrix = []
        for i in range(k):
            row = []
            for j in range(k):
                poly_seed = seed + struct.pack('>BB', i, j)
                expanded = shake256(poly_seed, self.params.n * 3)
                coeffs = []
                idx = 0
                
                while len(coeffs) < self.params.n and idx < len(expanded) - 2:
                    coeff = int.from_bytes(expanded[idx:idx+2], 'little')
                    if coeff < self.params.q:
                        coeffs.append(coeff)
                    idx += 1
                
                while len(coeffs) < self.params.n:
                    coeffs.append(0)
                
                row.append(Polynomial(np.array(coeffs[:self.params.n], dtype=np.int32), self.params.q))
            matrix.append(row)
        
        return PolynomialMatrix(matrix)
    
    def keygen(self) -> Tuple[bytes, bytes]:
        seed = self.rng.bytes(32)
        pk_seed, sk_seed = seed[:16], seed[16:]
        
        nonce = 0
        A = self._sample_matrix(pk_seed, self.params.k)
        
        s_polys = []
        for i in range(self.params.k):
            s_polys.append(self._sample_polynomial(sk_seed, nonce, self.params.eta1))
            nonce += 1
        
        e_polys = []
        for i in range(self.params.k):
            e_polys.append(self._sample_polynomial(sk_seed, nonce, self.params.eta1))
            nonce += 1
        
        s = PolynomialVector(s_polys)
        e = PolynomialVector(e_polys)
        
        t = A.multiply_vector(s) + e
        
        xmss_pk, xmss_sk = self.xmss.keygen()
        
        pk_data = {
            't': base64.b64encode(t.to_bytes()).decode(),
            'rho': base64.b64encode(pk_seed).decode(),
            'xmss_pk': base64.b64encode(xmss_pk).decode(),
            'params': {
                'n': self.params.n,
                'q': self.params.q,
                'k': self.params.k,
                'security_level': self.security_level.value
            }
        }
        
        sk_data = {
            's': base64.b64encode(s.to_bytes()).decode(),
            't': base64.b64encode(t.to_bytes()).decode(),
            'rho': base64.b64encode(pk_seed).decode(),
            'xmss_sk': base64.b64encode(xmss_sk).decode(),
            'z': base64.b64encode(shake256(t.to_bytes(), 32)).decode(),
            'params': pk_data['params']
        }
        
        return (json.dumps(pk_data).encode(), json.dumps(sk_data).encode())
    
    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        pk_data = json.loads(pk)
        
        t = PolynomialVector.from_bytes(
            base64.b64decode(pk_data['t']),
            self.params.k, self.params.n, self.params.q
        )
        rho = base64.b64decode(pk_data['rho'])
        
        m = self.rng.bytes(32)
        coins = shake256(m + shake256(pk, 32), 64)
        
        A = self._sample_matrix(rho, self.params.k)
        
        nonce = 0
        r_polys = []
        for i in range(self.params.k):
            r_polys.append(self._sample_polynomial(coins[:32], nonce, self.params.eta1))
            nonce += 1
        
        e1_polys = []
        for i in range(self.params.k):
            e1_polys.append(self._sample_polynomial(coins[:32], nonce, self.params.eta2))
            nonce += 1
        
        e2 = self._sample_polynomial(coins[:32], nonce, self.params.eta2)
        
        r = PolynomialVector(r_polys)
        e1 = PolynomialVector(e1_polys)
        
        u = A.multiply_vector(r) + e1
        v = t.dot(r) + e2
        
        m_coeffs = np.zeros(self.params.n, dtype=np.int32)
        for i in range(min(32, self.params.n)):
            if i < len(m):
                m_coeffs[i] = m[i] * (self.params.q // 256)
        
        m_poly = Polynomial(m_coeffs, self.params.q)
        v = v + m_poly
        
        u_compressed = u.compress(self.params.du)
        v_compressed = v.compress(self.params.dv)
        
        ct_data = {
            'u': [base64.b64encode(comp.tobytes()).decode() for comp in u_compressed],
            'v': base64.b64encode(v_compressed.tobytes()).decode(),
            'params': pk_data['params']
        }
        
        ciphertext = json.dumps(ct_data).encode()
        
        return (ciphertext, m)
    
    def decaps(self, ciphertext: bytes, sk: bytes) -> bytes:
        ct_data = json.loads(ciphertext)
        sk_data = json.loads(sk)
        
        s = PolynomialVector.from_bytes(
            base64.b64decode(sk_data['s']),
            self.params.k, self.params.n, self.params.q
        )
        
        u_compressed = []
        for comp_str in ct_data['u']:
            comp_bytes = base64.b64decode(comp_str)
            comp_array = np.frombuffer(comp_bytes, dtype=np.int32)
            if len(comp_array) < self.params.n:
                padded = np.zeros(self.params.n, dtype=np.int32)
                padded[:len(comp_array)] = comp_array
                comp_array = padded
            u_compressed.append(comp_array[:self.params.n])
        
        v_comp_bytes = base64.b64decode(ct_data['v'])
        v_compressed = np.frombuffer(v_comp_bytes, dtype=np.int32)
        if len(v_compressed) < self.params.n:
            padded = np.zeros(self.params.n, dtype=np.int32)
            padded[:len(v_compressed)] = v_compressed
            v_compressed = padded
        v_compressed = v_compressed[:self.params.n]
        
        u = PolynomialVector([Polynomial(np.zeros(self.params.n, dtype=np.int32), self.params.q) for _ in range(self.params.k)])
        u = u.decompress(u_compressed, self.params.du)
        
        base_poly = Polynomial(np.zeros(self.params.n, dtype=np.int32), self.params.q)
        v = base_poly.decompress(v_compressed, self.params.dv)
        
        m_poly = v - s.dot(u)
        
        m_bytes = bytearray()
        scale = self.params.q // 256
        for i in range(min(32, self.params.n)):
            coeff = int(m_poly.coeffs[i])
            if coeff > self.params.q // 2:
                coeff -= self.params.q
            
            if scale > 0:
                byte_val = (coeff + scale // 2) // scale
            else:
                byte_val = 0
            
            byte_val = max(0, min(255, byte_val))
            m_bytes.append(byte_val)
        
        return bytes(m_bytes)
    
    def sign(self, message: bytes, sk: bytes) -> bytes:
        sk_data = json.loads(sk)
        xmss_sk = base64.b64decode(sk_data['xmss_sk'])
        return self.xmss.sign(message, xmss_sk)
    
    def verify(self, message: bytes, signature: bytes, pk: bytes) -> bool:
        pk_data = json.loads(pk)
        xmss_pk = base64.b64decode(pk_data['xmss_pk'])
        return self.xmss.verify(message, signature, xmss_pk)

class QRCs:
    def __init__(self, security_level: SecurityLevel = SecurityLevel.NIST_5):
        self.security_level = security_level
        self.kem = KyberKEM(security_level)
        self.rng = SecureRandom()
        self._session_cache = {}
        self._lock = threading.Lock()
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return self.kem.keygen()
    
    def encrypt(self, plaintext: bytes, public_key: bytes, associated_data: bytes = b'') -> bytes:
        with self._lock:
            ciphertext, shared_secret = self.kem.encaps(public_key)
            
            nonce = self.rng.bytes(32)
            timestamp = struct.pack('>Q', int(time.time_ns()))
            
            aad_hash = shake256(associated_data, 32)
            
            key_material = shake256(shared_secret + nonce + timestamp + aad_hash, 64)
            encrypt_key = key_material[:32]
            mac_key = key_material[32:]
            
            compressed_plaintext = zlib.compress(plaintext, level=9)
            
            stream_key = encrypt_key
            encrypted_data = bytearray()
            
            for i, byte in enumerate(compressed_plaintext):
                stream_key = shake256(stream_key + struct.pack('>Q', i), 32)
                encrypted_data.append(byte ^ stream_key[i % 32])
            
            auth_data = ciphertext + nonce + timestamp + aad_hash + bytes(encrypted_data)
            mac = shake256(mac_key + auth_data, 32)
            
            envelope = {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'timestamp': base64.b64encode(timestamp).decode(),
                'aad_hash': base64.b64encode(aad_hash).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'mac': base64.b64encode(mac).decode(),
                'security_level': self.security_level.value,
                'version': 1
            }
            
            return base64.b64encode(json.dumps(envelope).encode())
    
    def decrypt(self, encrypted_data: bytes, private_key: bytes, associated_data: bytes = b'') -> bytes:
        with self._lock:
            envelope = json.loads(base64.b64decode(encrypted_data))
            
            ciphertext = base64.b64decode(envelope['ciphertext'])
            nonce = base64.b64decode(envelope['nonce'])
            timestamp = base64.b64decode(envelope['timestamp'])
            stored_aad_hash = base64.b64decode(envelope['aad_hash'])
            encrypted_payload = base64.b64decode(envelope['encrypted_data'])
            stored_mac = base64.b64decode(envelope['mac'])
            
            computed_aad_hash = shake256(associated_data, 32)
            if not ConstantTime.compare_bytes(stored_aad_hash, computed_aad_hash):
                raise ValueError("Associated data mismatch")
            
            shared_secret = self.kem.decaps(ciphertext, private_key)
            
            key_material = shake256(shared_secret + nonce + timestamp + computed_aad_hash, 64)
            encrypt_key = key_material[:32]
            mac_key = key_material[32:]
            
            auth_data = ciphertext + nonce + timestamp + computed_aad_hash + encrypted_payload
            computed_mac = shake256(mac_key + auth_data, 32)
            
            if not ConstantTime.compare_bytes(stored_mac, computed_mac):
                raise ValueError("MAC verification failed")
            
            stream_key = encrypt_key
            decrypted_data = bytearray()
            
            for i, byte in enumerate(encrypted_payload):
                stream_key = shake256(stream_key + struct.pack('>Q', i), 32)
                decrypted_data.append(byte ^ stream_key[i % 32])
            
            return zlib.decompress(bytes(decrypted_data))
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        return self.kem.sign(message, private_key)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self.kem.verify(message, signature, public_key)

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

def benchmark():
    levels = [SecurityLevel.NIST_1, SecurityLevel.NIST_3, SecurityLevel.NIST_5]
    message = b"Benchmark message for QRCs performance testing." * 100
    
    for level in levels:
        print(f"\nBenchmarking {level.name}:")
        system = QRCs(level)
        
        start = time.time()
        pk, sk = system.generate_keypair()
        keygen_time = time.time() - start
        
        start = time.time()
        ciphertext = system.encrypt(message, pk)
        encrypt_time = time.time() - start
        
        start = time.time()
        decrypted = system.decrypt(ciphertext, sk)
        decrypt_time = time.time() - start
        
        start = time.time()
        signature = system.sign(message, sk)
        sign_time = time.time() - start
        
        start = time.time()
        valid = system.verify(message, signature, pk)
        verify_time = time.time() - start
        
        print(f"  Keygen:  {keygen_time:.3f}s")
        print(f"  Encrypt: {encrypt_time:.3f}s")
        print(f"  Decrypt: {decrypt_time:.3f}s")
        print(f"  Sign:    {sign_time:.3f}s")
        print(f"  Verify:  {verify_time:.3f}s")
        print(f"  Correctness: {decrypted == message and valid}")

def test():
    system = QRCs(SecurityLevel.NIST_3)
    
    pk, sk = system.generate_keypair()
    
    messages = [
        b"Short message",
        b"Medium length message with some additional content",
        b"Very long message " * 100,
        b"",
        bytes(range(256))
    ]
    
    all_passed = True
    
    for i, message in enumerate(messages):
        try:
            associated_data = f"test_{i}".encode()
            
            ciphertext = system.encrypt(message, pk, associated_data)
            decrypted = system.decrypt(ciphertext, sk, associated_data)
            
            signature = system.sign(message, sk)
            valid = system.verify(message, signature, pk)
            
            test_passed = (message == decrypted and valid)
            print(f"Test {i+1}: {'PASS' if test_passed else 'FAIL'} (len={len(message)})")
            
            if not test_passed:
                all_passed = False
                
        except Exception as e:
            print(f"Test {i+1}: ERROR - {e}")
            all_passed = False
    
    print(f"\nOverall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")

def main():
    parser = argparse.ArgumentParser(description='QRCs - Quantum-Resistant Cryptographic System')
    
    parser.add_argument('command', choices=['keygen', 'encrypt', 'decrypt', 'sign', 'verify', 'test', 'benchmark'],
                       help='Operation to perform')
    parser.add_argument('-s', '--security', choices=['nist1', 'nist3', 'nist5'],
                       default='nist5', help='Security level')
    parser.add_argument('-k', '--key', help='Key file path')
    parser.add_argument('-f', '--file', help='Input file path')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--public-key', help='Public key file path')
    parser.add_argument('--private-key', help='Private key file path')
    parser.add_argument('--signature', help='Signature file path')
    
    args = parser.parse_args()
    
    security_map = {
        'nist1': SecurityLevel.NIST_1,
        'nist3': SecurityLevel.NIST_3,
        'nist5': SecurityLevel.NIST_5
    }
    security_level = security_map[args.security]
    
    try:
        if args.command == 'keygen':
            if not args.output:
                parser.error("keygen requires -o (base filename)")
            
            system = QRCs(security_level)
            public_key, private_key = system.generate_keypair()
            
            save_key(public_key, f"{args.output}.pub")
            save_key(private_key, f"{args.output}.priv")
            
            print(f"Keys generated: {args.output}.pub, {args.output}.priv")
            
        elif args.command == 'encrypt':
            if not all([args.file, args.output, args.public_key]):
                parser.error("encrypt requires -f, -o, and --public-key")
            
            encrypt_file(args.public_key, args.file, args.output, security_level)
            print(f"File encrypted: {args.output}")
            
        elif args.command == 'decrypt':
            if not all([args.file, args.output, args.private_key]):
                parser.error("decrypt requires -f, -o, and --private-key")
            
            decrypt_file(args.private_key, args.file, args.output, security_level)
            print(f"File decrypted: {args.output}")
            
        elif args.command == 'sign':
            if not all([args.file, args.output, args.private_key]):
                parser.error("sign requires -f, -o, and --private-key")
            
            system = QRCs(security_level)
            private_key = load_key(args.private_key)
            
            with open(args.file, 'rb') as f:
                message = f.read()
            
            signature = system.sign(message, private_key)
            save_key(signature, args.output)
            print(f"Signature created: {args.output}")
            
        elif args.command == 'verify':
            if not all([args.file, args.signature, args.public_key]):
                parser.error("verify requires -f, --signature, and --public-key")
            
            system = QRCs(security_level)
            public_key = load_key(args.public_key)
            signature = load_key(args.signature)
            
            with open(args.file, 'rb') as f:
                message = f.read()
            
            valid = system.verify(message, signature, public_key)
            print(f"Signature valid: {valid}")
            
        elif args.command == 'test':
            test()
            
        elif args.command == 'benchmark':
            benchmark()
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
