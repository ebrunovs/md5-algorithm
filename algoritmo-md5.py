# IFPB - Sistemas para Internet
# Disciplina: Segurança de Dados
# Prof.: Leandro Cavalcanti
# Aluno: Alessandro Rodrigues e Bruno Vinicius

import math

def algorythm_md5(message):

    BLOCK_SIZE = 512  #define o tamanho do bloco
    BIT_SIZE = 8 #define o tamanho do bit
    WORD_SIZE = 32 #define o tamanho da palavra
    MAX_SIZE = 448 #define o tamanho máximo

    # Inicializa as variáveis do MD5
    A, B, C, D = (
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476
    )

    # Valores de rotação para cada etapa do loop
    S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ]

    # Calcular os valores de K
    K = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    # Funções auxiliares para cada etapa do loop
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & z) | (y & ~z)
    def H(x, y, z): return x ^ y ^ z
    def I(x, y, z): return y ^ (x | ~z)

    # Rotação a esquerda, para misturar os bits
    def leftrotate(x, c):
        return ((x << c) | (x >> (WORD_SIZE - c))) & 0xFFFFFFFF

    # Processamento da mensagem
    message_bytes = bytearray(message, 'utf-8') #transforma a mensagem em bits
    message_size = len(message_bytes) * BIT_SIZE #guarda o tamanho da mensagem

    message_bytes.append(0x80) #adiciona um bit 1 ao final da mensagem

    while (len(message_bytes) * 8) % BLOCK_SIZE != MAX_SIZE: #adiciona 0's, padding, bits até que o tamanho da mensagem seja 448 bits
        message_bytes.append(0)

    message_bytes += message_size.to_bytes(8, byteorder='little') #adiciona comprimento original como 64 bits em little-endian
    
    for i in range(0, len(message_bytes), 64): #processa a mensagem em blocos de 512 bits
        block = message_bytes[i:i+64] #divide a mensagem em blocos de 512 bits
        words = [int.from_bytes(block[j:j+4], byteorder='little') for j in range(0, 64, 4)] # divide o bloco em 16 palavras de 32 bits cada
        
        a, b, c, d = A, B, C, D 
        
        # Loop principal
        for i in range(64):
            if 0 <= i <= 15:
                f = F(b, c, d)
                g = i
            elif 16 <= i <= 31:
                f = G(b, c, d)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                f = H(b, c, d)
                g = (3*i + 5) % 16
            elif 48 <= i <= 63:
                f = I(b, c, d)
                g = (7*i) % 16

            # Atualizar os valores temporários
            temp = d
            d = c
            c = b
            b = (b + leftrotate((a + f + K[i] + words[g]) & 0xFFFFFFFF, S[i])) & 0xFFFFFFFF
            a = temp
            
        # Atualizar os valores iniciais
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    # Concatenar os valores de A, B, C e D em hexadecimal
    md5_hash = ''.join(f'{x:02x}' for x in A.to_bytes(4, 'little') +
                                       B.to_bytes(4, 'little') +
                                       C.to_bytes(4, 'little') +
                                       D.to_bytes(4, 'little'))

    return md5_hash


# Teste
print(algorythm_md5("Instituto Federal da Paraiba"))



#Use o código abaixo para comparar os resultados.

#import hashlib
#texto = "Instituto Federal da Paraiba"
#hash_md5 = hashlib.md5(texto.encode()).hexdigest()
#print("MD5:", hash_md5)