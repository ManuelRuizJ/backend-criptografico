def obtener_llave_privada(P, G, llave_publica):
    for x in range(1, P):
        if pow(G, x, P) == llave_publica:
            return x
    return None


def factores_primos(n):
    factores = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factores.add(d)
            n //= d
        d += 1
    if n > 1:
        factores.add(n)
    return factores


def encontrar_generador(P):
    phi = P - 1
    factores = factores_primos(phi)

    for G in range(2, P):
        es_generador = True
        for q in factores:
            if pow(G, phi // q, P) == 1:
                es_generador = False
                break
        if es_generador:
            return G

    return None
