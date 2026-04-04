import re
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import date
import mysql.connector
app = Flask(__name__)
app.secret_key = "segredo_super_secreto"

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin",
        database="bms"
    )


# 🔐 LOGIN FUNCIONAL
@app.route('/', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':    
        email = request.form['email']
        senha = request.form['senha']

        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        usuario = cursor.fetchone()

        cursor.close()
        conn.close()

        # 🔴 EMAIL NÃO EXISTE
        if not usuario:
            return render_template('login.html', erro="Email não cadastrado")

        # 🔴 SENHA ERRADA
        if not check_password_hash(usuario['senha'], senha):
            return render_template('login.html', erro="Senha incorreta")

        # 🔴 USUÁRIO NÃO AUTORIZADO
        if usuario['ativo'] != 'A':
            return render_template('login.html', erro="Usuário não autorizado. Entre em contato com o administrador.")

        # 🔥 validação simples (com hash por enquanto)
        if usuario and check_password_hash(usuario['senha'], senha):

            session['usuario_id'] = usuario['id']
            session['usuario_nome'] = usuario['nome']
            session['usuario_email'] = usuario['email']

            return redirect('/agendamento')

        return render_template('login.html', erro="Login inválido")

    return render_template('login.html')


# 🔒 PROTEÇÃO
def protegido():
    return 'usuario_id' in session


# 📅 AGENDAMENTO
@app.route('/agendamento')
def agendamento():
    if not protegido(): 
        return redirect('/')
        
    # 1. Cria a conexão (Resolve o NameError: name 'db' is not defined)
    conn = get_db() 
    cursor = conn.cursor(dictionary=True)
    
    try:
        # 2. Busca Agendamentos com os nomes de Unidade e Operador (JOINs)
        cursor.execute("""
            SELECT a.*, u.nome as unidade_nome, o.nome as operador_nome 
            FROM agendamento a 
            LEFT JOIN unidades u ON a.unidades_id = u.id
            LEFT JOIN operadores o ON a.id_operadores = o.id
            ORDER BY a.data DESC, a.hora DESC
        """)
        lista_agendamentos = cursor.fetchall()
        
        # 3. Busca Operadores para o Combo do Modal
        cursor.execute("SELECT id, nome FROM operadores ORDER BY nome")
        lista_operadores = cursor.fetchall()
        
        # 4. Busca Unidades para o Combo do Modal
        cursor.execute("SELECT id, nome FROM unidades ORDER BY nome")
        lista_unidades = cursor.fetchall()

    except Exception as e:
        print(f"Erro no banco: {e}")
        lista_agendamentos, lista_operadores, lista_unidades = [], [], []
    finally:
        cursor.close()
        conn.close()

    # 5. Envia as TRÊS listas para o HTML
    return render_template('agendamento.html', 
                           agendamentos=lista_agendamentos, 
                           operadores=lista_operadores, 
                           unidades=lista_unidades)

# 💾 SALVAR
@app.route('/agendamento/salvar', methods=['POST'])
def salvar_agendamento():
    if not protegido(): return redirect('/')

    # 1. Captura os dados (Certifique-se que o nome 'id_operadores' bate com o HTML)
    id_ag       = request.form.get('id')
    nome        = request.form.get('nome')
    data        = request.form.get('data')
    hora        = request.form.get('hora')
    unidade     = request.form.get('unidades_id')
    operador    = request.form.get('id_operadores') # <--- ESTA LINHA
    idade       = request.form.get('idade')
    responsavel = request.form.get('responsavel')
    telefone    = request.form.get('telefone')
    confirmado  = 1 if request.form.get('confirmado') else 0
    compareceu  = 1 if request.form.get('compareceu') else 0

    # Tratamento para evitar erro se o combo estiver vazio (envia NULL para o banco)
    if not operador or operador == "":
        operador = None

    conn = get_db()
    cursor = conn.cursor()
    
    try:
        if id_ag:
            # UPDATE (Atenção à ordem: id_operadores está após unidades_id)
            sql = """UPDATE agendamento SET 
                     nome=%s, data=%s, hora=%s, unidades_id=%s, id_operadores=%s, 
                     idade=%s, responsavel=%s, telefone=%s, confirmacao=%s, compareceu=%s 
                     WHERE id=%s"""
            params = (nome, data, hora, unidade, operador, idade, responsavel, telefone, confirmado, compareceu, id_ag)
            cursor.execute(sql, params)
        else:
            # INSERT
            sql = """INSERT INTO agendamento 
                     (nome, data, hora, unidades_id, id_operadores, idade, responsavel, telefone, confirmacao, compareceu) 
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            params = (nome, data, hora, unidade, operador, idade, responsavel, telefone, confirmado, compareceu)
            cursor.execute(sql, params)
        
        conn.commit()
        print("Salvamento concluído com sucesso!") # Log para debug
    except Exception as e:
        print(f"ERRO AO SALVAR NO BANCO: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    return redirect('/agendamento')

# 🔍 VERIFICAÇÃO (OK)
@app.route('/agendamento/verificar')
def verificar_agendamento():

    data = request.args.get('data')
    hora = request.args.get('hora')
    unidade = request.args.get('unidades_id')
    id = request.args.get('id')

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT nome, telefone, responsavel
        FROM agendamento
        WHERE data = %s AND hora = %s AND unidades_id = %s
    """

    params = [data, hora, unidade]

    if id:
        query += " AND id != %s"
        params.append(id)

    cursor.execute(query, params)
    resultados = cursor.fetchall()

    cursor.close()
    conn.close()

    return {
        "conflito": len(resultados) > 0,
        "dados": resultados
    }


# DashBoard
# 📊 DASHBOARD
@app.route('/dashboard')
def dashboard():

    if not protegido():
        return redirect('/')

    return render_template('dashboard.html')

# Usuario
@app.route('/usuarios')
def usuarios():
    if not protegido():
        return redirect('/')

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT u.id, u.nome, u.email, u.telefone, u.id_perfil, u.ativo, p.nome AS perfil_nome
        FROM usuarios u
        LEFT JOIN perfil p ON p.id = u.id_perfil
        ORDER BY u.nome
    """)
    dados_usuarios = cursor.fetchall()

    cursor.execute("SELECT * FROM perfil ORDER BY nome")
    dados_perfis = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("usuarios.html", 
                           usuarios=dados_usuarios, 
                           perfis=dados_perfis)

# 🚪 LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
# DELETAR
@app.route('/agendamento/deletar/<int:id>')
def deletar_agendamento(id):

    if not protegido():
        return redirect('/')

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM agendamento WHERE id = %s", (id,))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/agendamento')

# ************  Agenda  **************************************
@app.route('/agenda')
def agenda():
    # 1. Pega os filtros da URL ou define padrões
    data_sel = request.args.get('data', date.today().isoformat())
    unidade_sel = request.args.get('unidade', '')

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 2. Busca Unidades para o Select
    cursor.execute("SELECT id, nome FROM unidades")
    unidades = cursor.fetchall()

    # 3. Busca na tabela 'agendamento' (Singular como você definiu)
    query = """
        SELECT a.*, u.nome as unidade_nome 
        FROM agendamento a 
        JOIN unidades u ON a.unidades_id = u.id 
        WHERE a.data = %s
    """
    params = [data_sel]

    if unidade_sel:
        query += " AND a.unidades_id = %s"
        params.append(unidade_sel)

    cursor.execute(query, params)
    # Aqui criamos a variável que o Python reconhece
    agendamento = cursor.fetchall() 

    cursor.close()
    conn.close()

    # 4. Envia para o HTML
    # IMPORTANTE: O HTML espera 'agendamentos' no loop {% for a in agendamentos %}
    return render_template('agenda.html', 
                           agendamentos=agendamento, # <--- A mágica acontece aqui
                           unidades=unidades,
                           data_selecionada=data_sel,
                           unidade_selecionada=unidade_sel)
# 💾 SALVAR NOVO USUÁRIO
@app.route('/usuarios/salvar', methods=['POST'])
def salvar_usuario():
    if not protegido():
        return redirect('/')

    id_usuario = request.form.get('id')
    nome = request.form['nome']
    email = request.form['email']
    senha_plana = request.form.get('senha')
    id_perfil = request.form['id_perfil']
    ativo = request.form.get('ativo', 'A')
    tel_raw = request.form.get('telefone', '')
    telefone_limpo = re.sub(r'\D', '', tel_raw)

    conn = get_db()
    cursor = conn.cursor()

    try:
        if id_usuario:  # --- MODO EDIÇÃO ---
            cursor.execute("""
                UPDATE usuarios SET nome=%s, email=%s, telefone=%s, id_perfil=%s, ativo=%s WHERE id=%s
            """, (nome, email, telefone_limpo, id_perfil, ativo, id_usuario))
        else:  # --- MODO INCLUSÃO ---
            hash_senha = generate_password_hash(senha_plana)
            cursor.execute("""
                INSERT INTO usuarios (nome, email, telefone, senha, id_perfil, ativo) VALUES (%s, %s, %s, %s, %s, %s)
            """, (nome, email, telefone_limpo, hash_senha, id_perfil, ativo))

        conn.commit()
    except Exception as e:
        print(f"Erro ao salvar: {e}")
        return redirect('/usuarios?erro=salvar')
    finally:
        cursor.close()
        conn.close()

    return redirect('/usuarios?ok=salvo')


# 🔑 ALTERAR SENHA
@app.route('/usuarios/alterar-senha', methods=['POST'])
def alterar_senha():
    if not protegido():
        return redirect('/')

    id_usuario = request.form.get('id')
    senha_antiga = request.form.get('senha_antiga')
    senha_nova = request.form.get('senha_nova')

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT senha FROM usuarios WHERE id = %s", (id_usuario,))
        usuario = cursor.fetchone()

        if not usuario or not check_password_hash(usuario['senha'], senha_antiga):
            return redirect('/usuarios?erro=senha_antiga')

        hash_nova = generate_password_hash(senha_nova)
        cursor.execute("UPDATE usuarios SET senha=%s WHERE id=%s", (hash_nova, id_usuario))
        conn.commit()
    except Exception as e:
        print(f"Erro ao alterar senha: {e}")
    finally:
        cursor.close()
        conn.close()

    return redirect('/usuarios?ok=senha_alterada')

# Deletar Usuario
@app.route('/usuarios/deletar/<int:id>')
def deletar_usuario(id):
    if not protegido():
        return redirect('/')

    conn = get_db()
    cursor = conn.cursor()
    try:
        # O segredo é garantir que o commit aconteça sem erros de sintaxe
        cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
        conn.commit() 
    except Exception as e:
        print(f"Erro ao deletar usuário: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    return redirect('/usuarios')    

# ************ OPERADORES    **************************************
# ************ OPERADORES (CÓDIGO COMPLETO) ****************************
@app.route('/operadores', methods=['GET', 'POST'])
def operadores():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    busca = request.args.get('q', '')

    if request.method == 'POST':
        dados = (
            request.form.get('nome'),
            request.form.get('codigo'),
            request.form.get('telefone'),
            request.form.get('nascimento') or None,
            request.form.get('endereco'),
            request.form.get('cidade'),
            request.form.get('uf'),
            request.form.get('cpf'),
            request.form.get('rg'),
            request.form.get('pix'),
            request.form.get('contato'),
            request.form.get('telefone_contato'),
            request.form.get('id_perfil') or None,
            request.form.get('status', 'A')
        )
        try:
            sql = """INSERT INTO operadores
                     (nome, codigo, telefone, nascimento, endereco, cidade, uf, cpf, rg, pix, contato, telefone_contato, id_perfil, status)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, dados)
            conn.commit()
        except Exception as e:
            print(f"Erro Insert: {e}")
            conn.close()
            return redirect(url_for('operadores') + '?erro=salvar')
        finally:
            conn.close()
        return redirect(url_for('operadores') + '?ok=salvo')

    # Ordenação
    colunas_validas = {'nome': 'o.nome', 'codigo': 'o.codigo', 'telefone': 'o.telefone',
                       'perfil': 'p.nome', 'status': 'o.status'}
    sort  = request.args.get('sort', 'nome')
    order = request.args.get('order', 'asc')
    if sort not in colunas_validas: sort = 'nome'
    if order not in ('asc', 'desc'): order = 'asc'
    order_sql = f"{colunas_validas[sort]} {order}"

    if busca:
        cursor.execute(f"""
            SELECT o.*, p.nome AS perfil_nome FROM operadores o
            LEFT JOIN perfil p ON p.id = o.id_perfil
            WHERE o.nome LIKE %s OR o.codigo LIKE %s ORDER BY {order_sql}
        """, (f'%{busca}%', f'%{busca}%'))
    else:
        cursor.execute(f"""
            SELECT o.*, p.nome AS perfil_nome FROM operadores o
            LEFT JOIN perfil p ON p.id = o.id_perfil
            ORDER BY {order_sql}
        """)

    lista = cursor.fetchall()

    cursor.execute("SELECT id, nome FROM perfil ORDER BY nome")
    perfis = cursor.fetchall()

    conn.close()
    return render_template('operadores.html', operadores=lista, perfis=perfis,
                           busca=busca, sort=sort, order=order)

@app.route('/operadores/editar/<int:id>', methods=['POST'])
def editar_operador(id):
    conn = get_db()
    cursor = conn.cursor()
    dados = (
        request.form.get('nome'), request.form.get('codigo'), request.form.get('telefone'),
        request.form.get('nascimento') or None, request.form.get('endereco'),
        request.form.get('cidade'), request.form.get('uf'), request.form.get('cpf'),
        request.form.get('rg'), request.form.get('pix'), request.form.get('contato'),
        request.form.get('telefone_contato'), request.form.get('id_perfil') or None,
        request.form.get('status', 'A'), id
    )
    try:
        sql = """UPDATE operadores SET nome=%s, codigo=%s, telefone=%s, nascimento=%s, endereco=%s,
                 cidade=%s, uf=%s, cpf=%s, rg=%s, pix=%s, contato=%s, telefone_contato=%s,
                 id_perfil=%s, status=%s WHERE id=%s"""
        cursor.execute(sql, dados)
        conn.commit()
    except Exception as e:
        print(f"Erro ao editar operador: {e}")
        return redirect(url_for('operadores') + '?erro=salvar')
    finally:
        conn.close()
    return redirect(url_for('operadores') + '?ok=salvo')

@app.route('/operadores/deletar/<int:id>')
def deletar_operador(id):
    if 'usuario_id' not in session: return redirect('/')
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM operadores WHERE id = %s", (id,))
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for('operadores'))

# ************ PERFIL **************************************
@app.route('/perfil')
def perfil():
    if not protegido():
        return redirect('/')

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    sort  = request.args.get('sort', 'nome')
    order = request.args.get('order', 'asc')
    if sort not in ('nome', 'nivel'): sort = 'nome'
    if order not in ('asc', 'desc'): order = 'asc'

    cursor.execute(f"SELECT * FROM perfil ORDER BY {sort} {order}")
    perfis = cursor.fetchall()
    conn.close()

    return render_template('perfil.html', perfis=perfis, sort=sort, order=order)


@app.route('/perfil/salvar', methods=['POST'])
def salvar_perfil():
    if not protegido():
        return redirect('/')

    id_perfil = request.form.get('id')
    nome      = request.form.get('nome', '').strip()
    nivel     = request.form.get('nivel') or None

    conn = get_db()
    cursor = conn.cursor()
    try:
        if id_perfil:
            cursor.execute("UPDATE perfil SET nome=%s, nivel=%s WHERE id=%s", (nome, nivel, id_perfil))
        else:
            cursor.execute("INSERT INTO perfil (nome, nivel) VALUES (%s, %s)", (nome, nivel))
        conn.commit()
    except Exception as e:
        print(f"Erro ao salvar perfil: {e}")
        return redirect('/perfil?erro=salvar')
    finally:
        cursor.close()
        conn.close()

    return redirect('/perfil?ok=salvo')


@app.route('/perfil/deletar/<int:id>')
def deletar_perfil(id):
    if not protegido():
        return redirect('/')

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM perfil WHERE id = %s", (id,))
        conn.commit()
    except Exception as e:
        print(f"Erro ao deletar perfil: {e}")
        return redirect('/perfil?erro=deletar')
    finally:
        cursor.close()
        conn.close()

    return redirect('/perfil?ok=deletado')


if __name__ == '__main__':
    app.run(debug=True)