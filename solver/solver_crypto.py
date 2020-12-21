from gmpy2 import isqrt
from Crypto.Util.number import *

## Wiener's Attack from https://github.com/pablocelayes/rsa-wiener-attack
def contfrac_to_rational (frac):
    if len(frac) == 0:
        return (0,1)
    num = frac[-1]
    denom = 1
    for _ in range(-2,-len(frac)-1,-1):
        num, denom = frac[_]*num+denom, num
    return (num,denom)

def is_perfect_square(n):
    h = n & 0xF #last hexadecimal "digit"

    if h > 9:
        return -1 # return immediately in 6 cases out of 16.

    if ( h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8 ):
        t = isqrt(n)
        if t*t == n:
            return t
        else:
            return -1
    return -1

def rational_to_contfrac(x,y):
    a = x//y
    pquotients = [a]
    while a * y != x:
        x,y = y,x-a*y
        a = x//y
        pquotients.append(a)
    return pquotients

def convergents_from_contfrac(frac):
    convs = [];
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs


def hack_RSA(e,n):
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)

    for (k,d) in convergents:

        #check if d is actually the key
        if k!=0 and (e*d-1)%k == 0:
            phi = (e*d-1)//k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s*s - 4*n
            if(discr>=0):
                t = is_perfect_square(discr)
                if t!=-1 and (s+t)%2==0:
                    # print("Hacked!")
                    return d


def decrypt(n, e, c):
    d = hack_RSA(e, n)
    m = pow(c, d, n)
    msg = long_to_bytes(m).decode()
    print(msg)

if __name__ == '__main__':
    n = 0x81fc1f45f7ef96961b3d7afafc34e7fd21d00e46e96255ae8d599437c264c68d8d0177cbc9549cbabf69a2880fe78ebda1c08f12b943c26885944ed9b757ecf50e84f7aa3e60972e1a1ef2ccb39c51fdc19f3666de1796c842316cefe4baa1c65cad56fe27c7973d217e3d68a462cd315db56a4740c8ee27fbbd0ea4bce28f3304fe345a36f408ce0789285e645a90e17c588bba8bafe2433a0780d62b1a53eea710e4f7392b50c3c0caa1312f911196e424444693476df9d7c912a2b067125a6bc05788e4bd5d54ef2a7cd6a5b35bba503c4ab1eacedcfc7c53f152302de92e60b54583c5031de1ee31e4d9f6d65d0ec206a0b15a0e2f11a051a7b7f96224d6d25ec1e2a539a775a81f1d69ec8d14870f110c80dd4f35c071f14f35459e12771fee58326c63e190ba8d58d5c8a4a7d6b817da2b782706200bdf25d28ee0e3b024ed9737780b1c1bdad8e0bcbd812dae016adc292b6e5000eda57840d0a3eef1e4006f9d7cf493436c279fc0021c351411af38d1ba881d70c44337da037318bbb449353750ab538f6dd850b407b6fc6fb4020a914b9b0c18104787e9a22f8323f4697fa4c1f4be9bf3fa63e82d1b275b03257ec0d4092bae3906ae057aebf60c3911b04a8ca58de97d79337d55c0c71273f10b72f1575d5e23a9970991028eceee631e3c095da964d970bc420dbdbb6472df5d39c8a3d28dea887ef923843d85
    e = 0x4ab1eb39b7b4e6e871dbe60fe046fbf42fc9f68f5c7ee2b9f54dc44ff59a6a6de286d9f6116fde7c53c42bf0809d778ae9d7f4eec21da4186c1b8db7caa3ae67bc1e29f33a0e755e3771163e8e5b5431655fef8d4212755e2825dfad49a6b5f90375c7f336e72cd61f60de1bb473520df1439be6390a04c2c1a07e8074d06c9d49e364a6f8c1ff0c3078a50606d4593e37915b5e6832ca08fe50bf21e7c9b50e8e20ca8210ac18479abbd9f7868befb935cfc2c6f4dc5ef4ba3e3d3aaeb4c9a7db403033a1f1ddd3d17fe0508fad91c55d1db37efa2481c908d3277697240b5c208cf66047a28dc2ba7d173083821e2514362fcd6b7bf152ad7dcc6df74923e0950617fc7d850ad4960f5f3faa79cc72300325d672c3e7856b7b62caa8263b8dc3014de4f3c7d8928baf6e06080661ea551448ffd5c8e4dd5d12ae2129a8ce44bd92d2929e2369ec09de7d4011f545a6e36a1199164f9e49703f6e66ea2720dfd382d781da600b10720f0cb48e329a3e33b04d2a496076c53132258b418888e5e64f5e95451c62a70abe83fa7acd89e374a10aaadd7adb565d2ae3aa0a9ab685a1f5682f44b4c4afbbd06e6984b383b31ae30e484156765f0c3345c47fc56a3796a3af56d534028a6ee6640629f5ac57c39c28cbaa7f2e93b7c02e040d39837834ea13b45768a5ad364f1c9f488b207d2dc09adeec4ba458b44bef91fe57f321
    c = 0x2b59cd67c22cc335264b6d8fb1c5f48afd66de43f6c7eb93d88316768c334e579fe71152862a1726f8684928a5b3d9a8fb12298e581f79045da4e0e904699170bd842d0a768ec5e8b3e17eac02954010b1f9bcccb9494deaa2f2e4924f15a399c97ae4ffd4b645e0badd7e741cd6f2369646f0adcc075a949b71bc329d728973f02102b3ef6d373f478d489bd047be040b044a82e8b0339029386c0faba35be0140c93ff775d6183930af9af35cd1e58c9a3e5894715e3f38f20459d36dddb3b63d226ea10ca06b92309ca5e1753a47cc087059601de2313226d82467f7d56c427e3ed8bbbd53dd70425000281acd20b5f2582bb75ee4277a3f0735926765fbb23e61b1f6c764766444faba537b677b4fbef2df18483451fb6a1177a0001ea8fa2c2703176db7677daeb8864e14d31b6e2a5fc71907c34921097cef5a314834aa63af827008e1773d4c26b72e0d58b9eba09bf85ca094f1afc89658aeb70de3bd6fc1e02d2db6c6dc5d4f491d750ab9ff4d0aaf3f133ec3051156dd9a4e270d41ab6846d66f29fdee4ce70bed1e91b89ef85d120c3dd6645ca2138f61e17be66084281714296c72e9d85237d73d1eb0ad5cdab8208b80d64543c29f5819696626506414e333811084e1b087028f9fb81103fb762097ab01ab8145b7ed5d650dd66c69d17c4b46b7e63d754f8ac24e8bfe206dbe69be9c6fa65ec7ea9ab816120
    decrypt(n, e, c)