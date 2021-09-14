
#!/usr/bin/python3

from Crypto.Util.number import getPrime
import libnum

#n = 0x6c451672f63e8ece9c3bde03f4483ed3d0e286c908a55b78e2d235021d95f4ba403e6cbaf14d15928867bb14ac855d7fbdc6ebbf99f151ab49832e70fdd19e8d29dfc4c4ca7329564a1d4182c1b02ef040d7e347e13db768203319357abe07b1ecaf5d099d3326d2639e0a5991ded8cb46b825709e0942e67f770520c26306e5f44c8ca72313106ff0dd9a90294edaa7e0097997ff2425c266e1d52c6935799a8cf7ebf12f88edd1dc683ffd252facf7fb3e9bca0467ebbb1dbe731e7ff9b245a78ca50e8f810202eef4e44ea0c01443584baf727b13aa2ba8978445345981a264fb15709f7b71b9611e0ef3f0b69c6a3ba9f12ea703bf742b3aa3fc1522d8d20466223bdfe5c2cc726d66a1416bcb26cab2976a915e6646143500e012896f355dea77e10a7ec36aacd547f66bf543a7d7841acbcd4f54ec267ad185984ef74a995ad7c141fa34f46956bb3d66db54c5f8f84252800d968cb1bd47b30030f3c54c8d45b2ed9e1809ae7aad3367a7d3b11c80539282b3deaa8e23bda567e09b87f33a60666e9247cc38c0d09666346d54e18fcd58e987fcfc1796ad4bc0cb498d5e100d640abdbdfcb45039464fe023679ad70fce916a5adffcb58520a22bbf1870cfe5fcbf651a30ace03a716b2a283bfaa076330abd502e1460f2182e64b565c3c1b3a77312fe98e77dd1b8eca1f80fe11d6f2675f9ea90cc533abd507dc285
#d0 = 0xa5cb79ef8059485d8ee47a9da0ed128ea83febf509c009aafcada53d35b28a7b020f7308078257aae306052f2086fa89ad9c810a4fd9afe498825bdc16b3050e6e26c2ebcc49de22ab34c09e53a699f29252adc01c1a3c036f192105154d94858bbaf42bf1dfadc0cdf7338c5c9e9fdf9c508bdc9d260df831b781e5ce33b874999ebb0f07d72bbe6d0971a2164b660e1d3df4cb265e8edbc63ec56c2b05ce2eb32cf9808931a3968f1045c38ea022bfd750c3925073d1c5befec2268efe0bd047f2411f081aee2b71c443c5fd26fed6a75c9e31b89dfd93180215eaa51117bcf4be54f140fc39322c5deb32ae1ec164f4ae451a1391d7b612645c06cdf83541

def find_d(N,e,d0,d0bits):
    for k in range(1,e):
        # Approximate d using N instead of phi
        d = ((k * N + 1) // e)
        print("approx d: %d" % d)
        print("d0: %d" % d0)
        # Replace the LSB of d by the known value
        d ^= (d % (1 << d0bits))       
        print("d1: %d" % d)
        d ^= d0
        print("d2: %d" % d)
        quit()

        if pow(pow(2,e,N),d,N) == 2:
            return d
    return 0


while True:
    p = 7549412987739264789105255689665490734925982778056985353697305487419259826686154098003904609557252710578917292695006541815476073682975843075081349637438349
    # getPrime(512)
    q = 11426944823142262745232497949551457374666135644497261731170014428825643853086473561920677557194174377824163622398204283029560187536366491042387731726114719
    n = p*q
    e = 17

    phi = (p-1)*(q-1)
    try:
        d = libnum.invmod(e, phi)
    except ValueError:
        continue
    
    if d:
        break

#d0 = d >> 511
d0 = int(bin(d)[512:],2)
#print(bin(d)[513:])
#print(len(bin(d)[513:]))



# print("p: %d" % p)
# print("q: %d" % q)
# print("n: %d" % n)
# print("e: %d" % e)
# print("d: %s" % hex(d))
# print("d bits: %d" % d.bit_length())
# print("d0: %s" % hex(d0))
# print("d0 bits: %d" % d0.bit_length())
res = find_d(n,e,d0, d0bits=d0.bit_length())
if res:
    print(res)