from typing import Union, overload

from Cryptodome.Util._raw_api import SmartPointer

Buffer = Union[bytes, bytearray, memoryview]

__all__ = ['CfbMode']


class CfbMode(object):
    block_size: int
    iv: Buffer
    IV: Buffer
    
    def __init__(self,
                 block_cipher: SmartPointer,
                 iv: Buffer,
                 segment_size: int) -> None: ...
    @overload
    def encrypt(self, plaintext: Buffer) -> bytes: ...
    @overload
    def encrypt(self, plaintext: Buffer, output: Union[bytearray, memoryview]) -> None: ...
    @overload
    def decrypt(self, plaintext: Buffer) -> bytes: ...
    @overload
    def decrypt(self, plaintext: Buffer, output: Union[bytearray, memoryview]) -> None: ...
