import oqs

# Definimos a instância do algoritmo XMSS
sigalg = "XMSS-SHA2_10_256"

# 1. Geração de Chaves e Assinatura (Lado do Emissor)
with oqs.StatefulSignature(sigalg) as signer:
    print(f"Gerando chaves para {sigalg} (isso cria a Merkle tree inicial)...")
    
    # A função generate_keypair() retorna a chave pública diretamente
    public_key = signer.generate_keypair()
    
    # Lendo o conteúdo de um arquivo (simulado em bytes aqui)
    mensagem = b"Conteudo do arquivo que sera protegido pelo algoritmo XMSS."
    
    print("Assinando a mensagem...")
    # O método sign gera a assinatura e AVANÇA o estado interno da chave secreta automaticamente
    signature = signer.sign(mensagem)
    print(f"Assinatura gerada com sucesso! Tamanho: {len(signature)} bytes.")

    # CRÍTICO: Exporta a chave secreta com o NOVO estado
    secret_key_atualizada = signer.export_secret_key()

# 2. Verificação (Lado do Receptor)
with oqs.StatefulSignature(sigalg) as verifier:
    print("\nVerificando a integridade do arquivo...")
    
    # A validação exige a mensagem original, a assinatura e a chave pública do emissor
    is_valid = verifier.verify(mensagem, signature, public_key)
    
    if is_valid:
        print("Sucesso: A assinatura XMSS é VÁLIDA.")
    else:
        print("Falha: A assinatura XMSS é INVÁLIDA.")
