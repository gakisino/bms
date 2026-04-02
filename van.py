import mysql.connector

def cadastrar_usuario():
    try:
        # 1. Estabelecendo a conexão
        conexao = mysql.connector.connect(
            host="localhost",
            user="root",      # Usuário padrão do MySQL
            password="",      # Senha (em branco no XAMPP por padrão)
            database="sistema_usuarios"
        )
        
        cursor = conexao.cursor()

        # 2. Coletando os dados do usuário
        print("--- Cadastro de Novo Usuário ---")
        nome = input("Digite o nome: ")
        telefone = input("Digite o telefone: ")

        # 3. Preparando o comando SQL
        comando_sql = "INSERT INTO usuarios (nome, telefone) VALUES (%s, %s)"
        valores = (nome, telefone)

        # 4. Executando e salvando
        cursor.execute(comando_sql, valores)
        conexao.commit() # Confirma a alteração no banco

        print(f"\nSucesso! Usuário {nome} cadastrado com ID {cursor.lastrowid}.")

    except mysql.connector.Error as erro:
        print(f"Erro ao conectar ou inserir: {erro}")

    finally:
        # 5. Sempre fechar a conexão
        if conexao.is_connected():
            cursor.close()
            conexao.close()

# Executar a rotina
if __name__ == "__main__":
    cadastrar_usuario()