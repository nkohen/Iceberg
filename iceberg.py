from typing import Tuple, List

import vpss
from musig import SessionContext as MuSigSessionContext, sign as musig_sign
from musig import bytes_from_int, int_from_bytes, n, InvalidContributionError
from vpss import RSSShare, VPSSCommitment, eval_lagrange

key_msg: bytes = 'Iceberg/keygen'.encode()

def key_gen(k: int, sk_k: RSSShare) -> Tuple[bytes, bytes]:
    (_, sk), (_, pk) = vpss.gen(k, sk_k, key_msg)
    return sk, pk

def pk_agg(t: int, mu: int, pks: List[VPSSCommitment]) -> bytes:
    assert vpss.verify(t, mu, pks)
    return vpss.agg(pks)

def nonce_gen(k: int, sk_k: RSSShare, sid: bytes) -> Tuple[bytes, bytes]:
    assert len(sid) == 32
    gen_share_1, comittment_1 = vpss.gen(k, sk_k, bytes_from_int(1) + sid)
    gen_share_2, comittment_2 = vpss.gen(k, sk_k, bytes_from_int(2) + sid)
    pubnonce = comittment_1.value + comittment_2.value
    secnonce = gen_share_1.value + gen_share_2.value
    return secnonce, pubnonce

def nonce_agg(t: int, mu: int, pubnonces: List[Tuple[int, bytes]]) -> bytes:
    commitments_1 = []
    commitments_2 = []
    for j, pubnonce in pubnonces:
        commitments_1.append(VPSSCommitment(j, pubnonce[0:33]))
        commitments_2.append(VPSSCommitment(j, pubnonce[33:66]))

    assert vpss.verify(t, mu, commitments_1)
    assert vpss.verify(t, mu, commitments_2)

    aggnonce = vpss.agg(commitments_1) + vpss.agg(commitments_2)
    return aggnonce

def sign(k: int, sk_k: RSSShare, sid: bytes, aggnonce: bytes, upper_session_ctx: MuSigSessionContext) -> bytes:
    assert len(sid) == 32
    sk, pk = key_gen(k, sk_k)
    gen_share_1, _ = vpss.gen(k, sk_k, bytes_from_int(1) + sid)
    gen_share_2, _ = vpss.gen(k, sk_k, bytes_from_int(2) + sid)
    secnonce = bytearray(gen_share_1.value + gen_share_2.value + pk)

    return musig_sign(secnonce, sk, upper_session_ctx)

def sign_agg(psigs: List[Tuple[int, bytes]]) -> bytes:
    s = 0
    for i, s_i in psigs:
        s_i = int_from_bytes(s_i)
        if s_i >= n:
            raise InvalidContributionError(i, "psig")
        indices = set([j for j, _ in psigs])
        s = (s + s_i * eval_lagrange(indices, i, 0)) % n

    return bytes_from_int(s)
