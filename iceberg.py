import random
import secrets
import time
from typing import Tuple, List

import vpss
from musig import SessionContext as MuSigSessionContext, sign as musig_sign, partial_sig_verify, individual_pk, \
    get_xonly_pk, key_agg_and_tweak, nonce_gen as musig_nonce_gen, nonce_agg as musig_nonce_agg, get_session_values, \
    has_even_y, point_mul, cpoint, get_session_key_agg_coeff, G, partial_sig_agg as musig_partial_sig_agg, \
    schnorr_verify
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

def sign(k: int, sk_k: RSSShare, sid: bytes, agg_pk: bytes, upper_session_ctx: MuSigSessionContext) -> bytes:
    assert len(sid) == 32
    sk, _ = key_gen(k, sk_k)
    gen_share_1, _ = vpss.gen(k, sk_k, bytes_from_int(1) + sid)
    gen_share_2, _ = vpss.gen(k, sk_k, bytes_from_int(2) + sid)

    (Q, gacc, _, b, R, e) = get_session_values(upper_session_ctx)
    k_1_ = int_from_bytes(gen_share_1.value)
    k_2_ = int_from_bytes(gen_share_2.value)
    if not 0 < k_1_ < n:
        raise ValueError('first secnonce value is out of range.')
    if not 0 < k_2_ < n:
        raise ValueError('second secnonce value is out of range.')
    k_1 = k_1_ if has_even_y(R) else n - k_1_
    k_2 = k_2_ if has_even_y(R) else n - k_2_
    d_ = int_from_bytes(sk)
    if not 0 < d_ < n:
        raise ValueError('secret key value is out of range.')
    a = get_session_key_agg_coeff(upper_session_ctx, cpoint(agg_pk))
    g = 1 if has_even_y(Q) else n - 1
    d = g * gacc * d_ % n
    s = (k_1 + b * k_2 + e * a * d) % n
    psig = bytes_from_int(s)
    R_s1 = point_mul(G, k_1_)
    R_s2 = point_mul(G, k_2_)
    assert R_s1 is not None
    assert R_s2 is not None
    # pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # Optional correctness check. The result of signing should pass signature verification.
    # assert partial_sig_verify_internal(psig, pubnonce, agg_pk, session_ctx)
    return psig

def sign_agg(psigs: List[Tuple[int, bytes]]) -> bytes:
    s = 0
    for i, s_i in psigs:
        s_i = int_from_bytes(s_i)
        if s_i >= n:
            raise InvalidContributionError(i, "psig")
        indices = set([j for j, _ in psigs])
        s = (s + s_i * eval_lagrange(indices, i, 0)) % n

    return bytes_from_int(s)

def test_random(n: int, t: int, mu: int) -> None:
    prf_sk_shares = vpss.key_gen(n, t, mu)
    prf_sk = {}
    pks = []
    for (k, sk_k) in enumerate(prf_sk_shares, 1):
        prf_sk[k] = sk_k
        _, pk_k = key_gen(k, sk_k)
        pks.append(VPSSCommitment(k, pk_k))
    pk_1 = pk_agg(t, mu, pks)

    sk_2 = secrets.token_bytes(32)
    pk_2 = individual_pk(sk_2)
    pubkeys = [pk_1, pk_2]

    sid = secrets.token_bytes(32)
    msg = secrets.token_bytes(32)
    v = secrets.randbelow(4)
    tweaks = [secrets.token_bytes(32) for _ in range(v)]
    is_xonly = [secrets.choice([False, True]) for _ in range(v)]
    aggpk = get_xonly_pk(key_agg_and_tweak(pubkeys, tweaks, is_xonly))

    nonce_gen_signers = random.sample(range(1, n+1), mu)
    pubnonces = []
    for k in nonce_gen_signers:
        _, pubnonce_k = nonce_gen(k, prf_sk[k], sid)
        pubnonces.append((k, pubnonce_k))
    pubnonce_1 = nonce_agg(t, mu, pubnonces)

    extra_in = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    secnonce_2, pubnonce_2 = musig_nonce_gen(sk_2, pk_2, aggpk, msg, extra_in.to_bytes(8, 'big'))
    pubnonces = [pubnonce_1, pubnonce_2]
    aggnonce = musig_nonce_agg(pubnonces)
    upper_ctx = MuSigSessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)

    signers = random.sample(range(1, n+1), mu)
    psigs = []
    for k in signers:
        psig_k = sign(k, prf_sk[k], sid, pk_1, upper_ctx)
        # sign is deterministic
        assert sign(k, prf_sk[k], sid, pk_1, upper_ctx) == psig_k
        psigs.append((k, psig_k))
    psig_1 = sign_agg(psigs)

    # signing is deterministic in aggregate with different signers
    concurrent_signers = random.sample(range(1, n+1), mu)
    psigs = []
    for k in concurrent_signers:
        psig_k = sign(k, prf_sk[k], sid, pk_1, upper_ctx)
        psigs.append((k, psig_k))
    assert sign_agg(psigs) == psig_1

    # aggregated partial sig is valid
    assert partial_sig_verify(psig_1, pubnonces, pubkeys, tweaks, is_xonly, msg, 0)

    # Wrong signer index
    assert not partial_sig_verify(psig_1, pubnonces, pubkeys, tweaks, is_xonly, msg, 1)

    # Wrong message
    assert not partial_sig_verify(psig_1, pubnonces, pubkeys, tweaks, is_xonly, secrets.token_bytes(32), 0)

    psig_2 = musig_sign(secnonce_2, sk_2, upper_ctx)
    assert partial_sig_verify(psig_2, pubnonces, pubkeys, tweaks, is_xonly, msg, 1)

    sig = musig_partial_sig_agg([psig_1, psig_2], upper_ctx)
    assert schnorr_verify(msg, aggpk, sig)
    print('Done!')