import oqs

# Primeiro algoritmo de XMSS em 
# liboqs/src/sig_stfl/sig_stfl.h
    # Função Hash: SHA256
    # Altura: 10 (2¹⁰ folhas)
    # Parâmetro de segurança = 256 bits
sigalg = "XMSS-SHA2_10_256"
        #"XMSS-SHA2_16_256"
        #"XMSS-SHA2_20_256"
        #"XMSS-SHAKE_10_256"
        #"XMSS-SHAKE_16_256"
        #"XMSS-SHAKE_20_256"
        #"XMSS-SHA2_10_512" # Usa SHA-512
        #"XMSS-SHA2_10_196" # Usa SHA-256 mas trunca para 192 bits
        #"XMSSMT-SHA2_20/2_256" # Multi-Tree como o SPHINCS+

# Geração de Chave

with oqs.StatefulSignature(sigalg) as signer:
    # liboqs-python/oqs/oqs.py, l. 999
    # existe um exemplo XMSS em liboqs-python/examples/stfl_sig.py

    public_key=signer.generate_keypair() 
        # liboqs-python/oqs/oqs.py, l. 482
        # Executa um algoritmo pseudoaleatório para criar as seeds
        # A partir das seeds, gera as 2^10 chaves WOTS+ das folhas
        # Monta a árvore até a raiz.
        # Constrói a chave pública concatenando a raiz com a seed
        #   Pública.
        # Constrói a chave secreta {idx,SK_seed,SK_prf,PUB_seed,Root}


# Geração de Assinatura
    with open("mensagem", "rb") as file_msg:
        message = file_msg.read()
        print("Mensagem Original: "+message.hex())

    n_assinaturas = 1
    print(f"\nIniciando processo de assinatura {n_assinaturas} vezes")
    #print("\nAssinando a mensagem...")

    for i in range(n_assinaturas):
        signature = signer.sign(message)
            # liboqs-python/oqs/oqs.py, l. 717
            # Passa os bytes do arquivo para a biblioteca em C assinar

        secret_key_atualizada = signer.export_secret_key()
            # liboqs-python/oqs/oqs.py, l. 1210
            # Exporta a chave secreta com o novo estado.
            # Atualiza o idx e demais parâmetros da chave.
            # raiz, função e sementes (32 bytes - 2 linhas xxd)

        with open("chave_secreta", "wb") as file_sk:
            file_sk.write(secret_key_atualizada)
            print(f"Chave secreta gerada com sucesso. \n Tamanho: {len(secret_key_atualizada)} bytes. \n Chave Secreta:"+secret_key_atualizada.hex())

        with open("assinatura", "wb") as file_sig:
            file_sig.write(signature)
            print(f"Assiantura gerada com sucesso. \n Tamanho: {len(signature)} bytes. \n Assinatura: "+signature.hex())
        print(f"Assinatura {i+1} concluída. O índice interno avançou")


input("Aperte Enter para seguir para a verificação.")
# Verificação de assinatura
with oqs.StatefulSignature(sigalg) as verifier:
    print("\nVerificando a Integridade do arquivo...");

    with open("assinatura", "rb") as file_sig:
        signature = file_sig.read()
    with open("mensagem", "rb") as file_msg:
        message = file_msg.read()
        
    resultado_valido = verifier.verify(message, signature, public_key)
        # liboqs-python/oqs/oqs.py, l. 1195
        # Descompacta mensagem (idx, aleatoriedade(r), assinatura, caminho).
        # recalcula a folha usando o r e sobe até a raiz. Compara.

    if resultado_valido: # a função retorna um booleano
        print("Sucesso: A assinatura XMSS é Válida.")
    else:
        print("Falha: A assinatura XMSS é Inválida.")
