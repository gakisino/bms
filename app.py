import re
from functools import wraps
from contextlib import contextmanager
from decimal import Decimal, ROUND_HALF_UP
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import date, datetime
import mysql.connector
import os    

app = Flask(__name__)
app.secret_key = "segredo_super_secreto"

# Filtro customizado para formatar moeda brasileira
def formatar_moeda(valor):
    """Formata valor para moeda brasileira: R$ 1.234,56"""
    if valor is None or valor == '':
        return '—'
    try:
        valor_float = float(valor)
        return f"R$ {valor_float:,.2f}".replace(',', 'TEMP').replace('.', ',').replace('TEMP', '.')
    except (ValueError, TypeError):
        return '—'

app.jinja_env.filters['moeda'] = formatar_moeda

# Cache de IDs das rotinas (carregado dinamicamente do banco)
ROTINAS_CACHE = {}

def get_db():
    return mysql.connector.connect(
        # O os.getenv tenta ler a variável do servidor. 
        # Se não existir (no seu PC), ele usa o que está depois da vírgula.
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', 'admin'),
        database=os.getenv('DB_DATABASE', 'bms')
    )

@contextmanager
def get_cursor(dictionary=True):

    
    conn = get_db()
    cursor = conn.cursor(dictionary=dictionary)
    try:
        yield conn, cursor
        conn.commit()
    except Exception:      
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

def carregar_rotinas_cache():
    """Carrega mapeamento apelido → ID das rotinas do banco de dados"""
    global ROTINAS_CACHE
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("SELECT id, apelido FROM rotinas WHERE ativo = 1")
            ROTINAS_CACHE = {row['apelido']: row['id'] for row in cursor.fetchall()}
            print(f"[OK] Rotinas carregadas no cache: {ROTINAS_CACHE}")
    except Exception as e:
        print(f"[AVISO] Erro ao carregar cache de rotinas: {e}")
        ROTINAS_CACHE = {}

def get_rotina_id(apelido):
    """Obtém ID de uma rotina pelo apelido (usa cache)"""
    if not ROTINAS_CACHE:
        carregar_rotinas_cache()
    return ROTINAS_CACHE.get(apelido)


# Context processor para injetar funções nos templates
@app.context_processor
def injetar_permissoes():
    def tem_acesso_rotina(id_rotina):
        """Verifica se o usuário logado tem acesso a uma rotina (utilizado nos templates)"""
        if 'rotinas_acesso' not in session:
            return True  # Se não houver dados, libera acesso por enquanto
        return int(id_rotina) in session.get('rotinas_acesso', [])

    def tem_acesso_alteracao(nome_rotina):
        """Verifica se o usuário logado tem acesso de ALTERAÇÃO a uma rotina"""
        if 'usuario_id' not in session:
            return False
        return verificar_acesso_alteracao(session['usuario_id'], nome_rotina)

    return dict(
        tem_acesso_rotina=tem_acesso_rotina,
        tem_acesso_alteracao=tem_acesso_alteracao,
        rotinas_acesso=session.get('rotinas_acesso', []),
        get_rotina_id=get_rotina_id  # Passa função para buscar ID pelo nome no template
    )


# Carrega cache de rotinas na inicialização
carregar_rotinas_cache()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def acesso_alteracao_required(nome_rotina):
    """Decorador que verifica acesso de ALTERAÇÃO a uma rotina (não apenas leitura)"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'usuario_id' not in session:
                return redirect(url_for('login'))

            if not verificar_acesso_alteracao(session['usuario_id'], nome_rotina):
                flash('Você tem apenas acesso de leitura a esta rotina.', 'erro')
                referrer = request.referrer or '/dashboard'
                return redirect(referrer)

            return f(*args, **kwargs)
        return decorated
    return decorator


def acesso_rotina_required(nome_rotina):
    """Decorador que verifica acesso a uma rotina específica pelo nome"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'usuario_id' not in session:
                return redirect(url_for('login'))

            # Busca ID da rotina dinamicamente
            id_rotina = get_rotina_id(nome_rotina)
            if not id_rotina:
                print(f"[AVISO] Rotina '{nome_rotina}' não encontrada no banco")
                flash('Rotina não configurada no sistema.', 'erro')
                return redirect('/dashboard')

            acesso = verificar_acesso_rotina(session['usuario_id'], id_rotina)
            if not acesso:
                flash('Você não tem permissão para acessar esta rotina.', 'erro')
                return redirect('/dashboard')

            # Armazena tipo de acesso na sessão para a rotina
            session[f'acesso_rotina_{id_rotina}'] = acesso
            return f(*args, **kwargs)
        return decorated
    return decorator


# 🔐 LOGIN FUNCIONAL
@app.route('/', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        with get_cursor() as (_, cursor):
            cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
            usuario = cursor.fetchone()

        # 🔴 EMAIL NÃO EXISTE
        if not usuario:
            return render_template('login.html', erro="Email não cadastrado")

        # 🔴 USUÁRIO JÁ BLOQUEADO
        if usuario['ativo'] == 'B':
            return render_template('login.html', erro="Usuário bloqueado. Entre em contato com o administrador.")

        # 🔴 USUÁRIO INATIVO
        if usuario['ativo'] != 'A':
            return render_template('login.html', erro="Usuário não autorizado. Entre em contato com o administrador.")

        # 🔴 SENHA ERRADA
        if not check_password_hash(usuario['senha'], senha):
            novas_tentativas = usuario['tentativas'] + 1

            if novas_tentativas >= 5:
                with get_cursor() as (_, cursor):
                    cursor.execute(
                        "UPDATE usuarios SET tentativas=%s, ativo='B' WHERE id=%s",
                        (novas_tentativas, usuario['id'])
                    )
                return render_template('login.html', erro="Usuário bloqueado após 5 tentativas inválidas. Entre em contato com o administrador.")

            with get_cursor() as (_, cursor):
                cursor.execute(
                    "UPDATE usuarios SET tentativas=%s WHERE id=%s",
                    (novas_tentativas, usuario['id'])
                )
            restantes = 5 - novas_tentativas
            return render_template('login.html', erro=f"Senha incorreta. {restantes} tentativa(s) restante(s).")

        # ✅ LOGIN OK — zera tentativas e abre sessão
        with get_cursor() as (_, cursor):
            cursor.execute("UPDATE usuarios SET tentativas=0 WHERE id=%s", (usuario['id'],))

        session['usuario_id']    = usuario['id']
        session['usuario_nome']  = usuario['nome']
        session['usuario_email'] = usuario['email']

        # Carrega rotinas que o usuário tem acesso
        rotinas_acesso = obter_rotinas_acesso_usuario(usuario['id'])
        session['rotinas_acesso'] = rotinas_acesso

        return redirect('/agendamento')

    return render_template('login.html')


# 📅 AGENDAMENTO
@app.route('/agendamento')
@login_required
@acesso_alteracao_required('visitas')
def agendamento():
    sort = request.args.get('sort', 'data')
    order = request.args.get('order', 'asc')
    data_filtro = request.args.get('data', '')
    unidade_filtro = request.args.get('unidade', '')

    if sort not in ('data', 'hora', 'nome', 'responsavel', 'id_operadores', 'unidades_id'):
        sort = 'data'
    if order not in ('asc', 'desc'):
        order = 'asc'

    with get_cursor() as (_, cursor):
        # Monta ORDER BY: campo escolhido + data + hora
        order_by = f"a.{sort} {order}, a.data ASC, a.hora ASC"

        # Monta WHERE com filtros opcionais
        where_clauses = []
        params = []

        if data_filtro:
            where_clauses.append("a.data = %s")
            params.append(data_filtro)

        if unidade_filtro:
            where_clauses.append("a.unidades_id = %s")
            params.append(unidade_filtro)

        where_clause = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        query = f"""
            SELECT a.id, a.data, a.hora, a.nome, a.telefone, a.idade, a.responsavel, a.observacao,
                   a.unidades_id, a.id_operadores,
                   COALESCE(a.confirmacao, 'N') as confirmado,
                   COALESCE(a.compareceu, 'N') as compareceu,
                   u.nome as unidade_nome, u.sigla as unidade_sigla, u.cor_bg, u.cor_texto, o.nome as operador_nome
            FROM agendamento a
            LEFT JOIN unidades u ON a.unidades_id = u.id
            LEFT JOIN operadores o ON a.id_operadores = o.id
            {where_clause}
            ORDER BY {order_by}
        """

        cursor.execute(query, params)
        lista_agendamentos = cursor.fetchall()

        # Contagens para o resumo
        query_count = f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN a.confirmacao = 'S' THEN 1 ELSE 0 END) as confirmados,
                SUM(CASE WHEN a.compareceu = 'S' THEN 1 ELSE 0 END) as compareceu_count
            FROM agendamento a
            {where_clause}
        """
        cursor.execute(query_count, params)
        resumo = cursor.fetchone()

        cursor.execute("SELECT id, nome FROM operadores ORDER BY nome")
        lista_operadores = cursor.fetchall()
        cursor.execute("SELECT id, nome FROM unidades ORDER BY nome")
        lista_unidades = cursor.fetchall()

    return render_template('agendamento.html',
                           agendamentos=lista_agendamentos,
                           operadores=lista_operadores,
                           unidades=lista_unidades,
                           sort=sort,
                           order=order,
                           data_filtro=data_filtro,
                           unidade_filtro=unidade_filtro,
                           resumo_total=resumo['total'] or 0,
                           resumo_confirmados=resumo['confirmados'] or 0,
                           resumo_compareceu=resumo['compareceu_count'] or 0)


# 💾 SALVAR AGENDAMENTO
@app.route('/agendamento/salvar', methods=['POST'])
@login_required
@acesso_alteracao_required('visitas')
def salvar_agendamento():
    id_ag       = request.form.get('id')
    nome        = request.form.get('nome', '').strip()
    data        = request.form.get('data')
    hora        = request.form.get('hora')
    unidade     = request.form.get('unidades_id')
    operador    = request.form.get('id_operadores')
    idade       = request.form.get('idade')
    responsavel = request.form.get('responsavel')
    telefone    = re.sub(r'\D', '', request.form.get('telefone', ''))  # Remove máscara
    observacao  = request.form.get('observacao')
    redirect_url = request.form.get('redirect_url', '/agendamento?ok=salvo')

    # Validações
    if not nome:
        error_redirect = f"{redirect_url}?erro=nome_vazio" if '?' not in redirect_url else f"{redirect_url}&erro=nome_vazio"
        return redirect(error_redirect)

    if not telefone:
        error_redirect = f"{redirect_url}?erro=telefone_vazio" if '?' not in redirect_url else f"{redirect_url}&erro=telefone_vazio"
        return redirect(error_redirect)

    if not operador:
        error_redirect = f"{redirect_url}?erro=operador_vazio" if '?' not in redirect_url else f"{redirect_url}&erro=operador_vazio"
        return redirect(error_redirect)

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            if id_ag:
                cursor.execute("""UPDATE agendamento SET
                    nome=%s, data=%s, hora=%s, unidades_id=%s, id_operadores=%s,
                    idade=%s, responsavel=%s, telefone=%s, observacao=%s
                    WHERE id=%s""",
                    (nome, data, hora, unidade, operador, idade, responsavel, telefone, observacao, id_ag))
            else:
                cursor.execute("""INSERT INTO agendamento
                    (nome, data, hora, unidades_id, id_operadores, idade, responsavel, telefone, observacao)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (nome, data, hora, unidade, operador, idade, responsavel, telefone, observacao))
    except Exception as e:
        print(f"ERRO AO SALVAR AGENDAMENTO: {e}")
        error_redirect = redirect_url if '?' in redirect_url else f"{redirect_url}?erro=salvar"
        return redirect(error_redirect)

    success_redirect = redirect_url if '?' in redirect_url else f"{redirect_url}?ok=salvo"
    return redirect(success_redirect)


# 🔍 VERIFICAÇÃO
@app.route('/agendamento/verificar')
@login_required
def verificar_agendamento():
    data    = request.args.get('data')
    hora    = request.args.get('hora')
    unidade = request.args.get('unidades_id')
    id      = request.args.get('id')

    query  = "SELECT nome, telefone, responsavel FROM agendamento WHERE data=%s AND hora=%s AND unidades_id=%s"
    params = [data, hora, unidade]
    if id:
        query += " AND id != %s"
        params.append(id)

    with get_cursor() as (_, cursor):
        cursor.execute(query, params)
        resultados = cursor.fetchall()

    return {"conflito": len(resultados) > 0, "dados": resultados}


# 📊 DASHBOARD
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


# 👥 USUÁRIOS
@app.route('/usuarios')
@login_required
@acesso_rotina_required('usuarios')
def usuarios():
    with get_cursor() as (_, cursor):
        cursor.execute("""
            SELECT u.id, u.nome, u.email, u.telefone, u.id_perfil, u.ativo,
                   p.nome AS perfil_nome, p.cor_bg, p.cor_texto
            FROM usuarios u
            LEFT JOIN perfil p ON p.id = u.id_perfil
            ORDER BY u.nome
        """)
        dados_usuarios = cursor.fetchall()
        cursor.execute("SELECT * FROM perfil ORDER BY nome")
        dados_perfis = cursor.fetchall()

    return render_template("usuarios.html", usuarios=dados_usuarios, perfis=dados_perfis)


# 🚪 LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/api/tempo-inatividade')
@login_required
def tempo_inatividade():
    """Retorna o tempo de inatividade em segundos"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("SELECT inatividade FROM parametros LIMIT 1")
            resultado = cursor.fetchone()
            if resultado:
                tempo = int(resultado['inatividade']) if resultado['inatividade'] else 1800
                print(f"[OK] Inatividade carregada: {tempo} segundos")
            else:
                tempo = 1800
                print("[AVISO] Nenhum registro em parametros, usando padrão")
            return jsonify({'tempo_segundos': tempo})
    except Exception as e:
        print(f"[ERRO] tempo_inatividade: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'tempo_segundos': 1800})


# 🗑️ DELETAR AGENDAMENTO
@app.route('/agendamento/deletar/<int:id>')
@login_required
@acesso_alteracao_required('visitas')
def deletar_agendamento(id):
    with get_cursor(dictionary=False) as (_, cursor):
        cursor.execute("DELETE FROM agendamento WHERE id = %s", (id,))
    return redirect('/agendamento?ok=deletado')


# ✅ TOGGLE CONFIRMAÇÃO
@app.route('/agendamento/toggle-confirmacao', methods=['POST'])
@login_required
@acesso_alteracao_required('visitas')
def toggle_confirmacao():
    id_ag = request.form.get('id')
    confirmacao = request.form.get('confirmacao')

    with get_cursor(dictionary=False) as (_, cursor):
        cursor.execute("UPDATE agendamento SET confirmacao = %s WHERE id = %s", (confirmacao, id_ag))
    return jsonify({'status': 'ok'})


# ✅ TOGGLE COMPARECEU
@app.route('/agendamento/toggle-compareceu', methods=['POST'])
@login_required
@acesso_alteracao_required('visitas')
def toggle_compareceu():
    id_ag = request.form.get('id')
    compareceu = request.form.get('compareceu')

    with get_cursor(dictionary=False) as (_, cursor):
        cursor.execute("UPDATE agendamento SET compareceu = %s WHERE id = %s", (compareceu, id_ag))
    return jsonify({'status': 'ok'})


# 📆 AGENDA
@app.route('/agenda')
@login_required
def agenda():
    data_sel    = request.args.get('data', date.today().isoformat())
    unidade_sel = request.args.get('unidade', '')

    query  = """SELECT a.*, u.nome as unidade_nome, u.sigla, u.cor_bg, u.cor_texto FROM agendamento a
                JOIN unidades u ON a.unidades_id = u.id WHERE a.data = %s"""
    params = [data_sel]
    if unidade_sel:
        query += " AND a.unidades_id = %s"
        params.append(unidade_sel)

    with get_cursor() as (_, cursor):
        cursor.execute("SELECT id, nome FROM unidades")
        unidades = cursor.fetchall()
        cursor.execute(query, params)
        agendamentos = cursor.fetchall()

    return render_template('agenda.html',
                           agendamentos=agendamentos,
                           unidades=unidades,
                           data_selecionada=data_sel,
                           unidade_selecionada=unidade_sel)


# 💾 SALVAR USUÁRIO
@app.route('/usuarios/salvar', methods=['POST'])
@login_required
@acesso_alteracao_required('usuarios')
def salvar_usuario():
    id_usuario     = request.form.get('id')
    nome           = request.form['nome']
    email          = request.form['email']
    senha_plana    = request.form.get('senha')
    id_perfil      = request.form['id_perfil']
    ativo          = request.form.get('ativo', 'A')
    telefone_limpo = re.sub(r'\D', '', request.form.get('telefone', ''))

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            if id_usuario:
                cursor.execute("""UPDATE usuarios SET nome=%s, email=%s, telefone=%s, id_perfil=%s, ativo=%s WHERE id=%s""",
                               (nome, email, telefone_limpo, id_perfil, ativo, id_usuario))
            else:
                cursor.execute("""INSERT INTO usuarios (nome, email, telefone, senha, id_perfil, ativo) VALUES (%s,%s,%s,%s,%s,%s)""",
                               (nome, email, telefone_limpo, generate_password_hash(senha_plana), id_perfil, ativo))
    except Exception as e:
        print(f"Erro ao salvar usuário: {e}")
        return redirect('/usuarios?erro=salvar')

    return redirect('/usuarios?ok=salvo')


# 🔑 ALTERAR SENHA
@app.route('/usuarios/alterar-senha', methods=['POST'])
@login_required
def alterar_senha():
    id_usuario  = request.form.get('id')
    senha_antiga = request.form.get('senha_antiga')
    senha_nova   = request.form.get('senha_nova')

    with get_cursor() as (_, cursor):
        cursor.execute("SELECT senha FROM usuarios WHERE id = %s", (id_usuario,))
        usuario = cursor.fetchone()

    if not usuario or not check_password_hash(usuario['senha'], senha_antiga):
        return redirect('/usuarios?erro=senha_antiga')

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("UPDATE usuarios SET senha=%s WHERE id=%s", (generate_password_hash(senha_nova), id_usuario))
    except Exception as e:
        print(f"Erro ao alterar senha: {e}")
        return redirect('/usuarios?erro=salvar')

    return redirect('/usuarios?ok=senha_alterada')


# 🗑️ DELETAR USUÁRIO
@app.route('/usuarios/deletar/<int:id>')
@login_required
def deletar_usuario(id):
    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    except Exception as e:
        print(f"Erro ao deletar usuário: {e}")
        return redirect('/usuarios?erro=deletar')
    return redirect('/usuarios?ok=deletado')


# ************ OPERADORES **************************************
@app.route('/operadores', methods=['GET', 'POST'])
@login_required
def operadores():
    busca = request.args.get('q', '')

    if request.method == 'POST':
        dados = (
            request.form.get('nome'), request.form.get('codigo'), request.form.get('telefone'),
            request.form.get('nascimento') or None, request.form.get('endereco'),
            request.form.get('cidade'), request.form.get('uf'), request.form.get('cpf'),
            request.form.get('rg'), request.form.get('pix'), request.form.get('contato'),
            request.form.get('telefone_contato'), request.form.get('id_perfil') or None,
            request.form.get('id_usuarios') or None, request.form.get('status', 'A')
        )
        try:
            with get_cursor(dictionary=False) as (_, cursor):
                cursor.execute("""INSERT INTO operadores
                    (nome, codigo, telefone, nascimento, endereco, cidade, uf, cpf, rg, pix, contato, telefone_contato, id_perfil, id_usuarios, status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", dados)
        except Exception as e:
            print(f"Erro ao inserir operador: {e}")
            return redirect(url_for('operadores', erro='salvar'))
        return redirect(url_for('operadores', ok='salvo'))

    colunas_validas = {'nome': 'o.nome', 'codigo': 'o.codigo', 'telefone': 'o.telefone',
                       'perfil': 'p.nome', 'status': 'o.status'}
    sort  = request.args.get('sort', 'nome')
    order = request.args.get('order', 'asc')
    if sort not in colunas_validas: sort = 'nome'
    if order not in ('asc', 'desc'): order = 'asc'
    order_sql = f"{colunas_validas[sort]} {order}"

    with get_cursor() as (_, cursor):
        if busca:
            cursor.execute(f"""SELECT o.*, p.nome AS perfil_nome, p.cor_bg, p.cor_texto FROM operadores o
                LEFT JOIN perfil p ON p.id = o.id_perfil
                WHERE o.nome LIKE %s OR o.codigo LIKE %s ORDER BY {order_sql}""",
                (f'%{busca}%', f'%{busca}%'))
        else:
            cursor.execute(f"""SELECT o.*, p.nome AS perfil_nome, p.cor_bg, p.cor_texto FROM operadores o
                LEFT JOIN perfil p ON p.id = o.id_perfil ORDER BY {order_sql}""")
        lista = cursor.fetchall()
        cursor.execute("SELECT id, nome FROM perfil ORDER BY nome")
        perfis = cursor.fetchall()
        cursor.execute("SELECT id, nome FROM usuarios ORDER BY nome")
        usuarios = cursor.fetchall()

    return render_template('operadores.html', operadores=lista, perfis=perfis, usuarios=usuarios,
                           busca=busca, sort=sort, order=order)


@app.route('/operadores/editar/<int:id>', methods=['POST'])
@login_required
def editar_operador(id):
    dados = (
        request.form.get('nome'), request.form.get('codigo'), request.form.get('telefone'),
        request.form.get('nascimento') or None, request.form.get('endereco'),
        request.form.get('cidade'), request.form.get('uf'), request.form.get('cpf'),
        request.form.get('rg'), request.form.get('pix'), request.form.get('contato'),
        request.form.get('telefone_contato'), request.form.get('id_perfil') or None,
        request.form.get('id_usuarios') or None, request.form.get('status', 'A'), id
    )
    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("""UPDATE operadores SET nome=%s, codigo=%s, telefone=%s, nascimento=%s, endereco=%s,
                cidade=%s, uf=%s, cpf=%s, rg=%s, pix=%s, contato=%s, telefone_contato=%s,
                id_perfil=%s, id_usuarios=%s, status=%s WHERE id=%s""", dados)
    except Exception as e:
        print(f"Erro ao editar operador: {e}")
        return redirect(url_for('operadores', erro='salvar'))
    return redirect(url_for('operadores', ok='salvo'))


@app.route('/operadores/deletar/<int:id>')
@login_required
def deletar_operador(id):
    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("DELETE FROM operadores WHERE id = %s", (id,))
    except Exception as e:
        print(f"Erro ao deletar operador: {e}")
        return redirect(url_for('operadores', erro='deletar'))
    return redirect(url_for('operadores', ok='deletado'))


# ************ PERFIL **************************************
@app.route('/perfil')
@login_required
@acesso_rotina_required('perfis')
def perfil():
    sort  = request.args.get('sort', 'nome')
    order = request.args.get('order', 'asc')
    if sort not in ('nome', 'nivel'): sort = 'nome'
    if order not in ('asc', 'desc'): order = 'asc'

    with get_cursor() as (_, cursor):
        cursor.execute(f"SELECT * FROM perfil ORDER BY {sort} {order}")
        perfis = cursor.fetchall()

    return render_template('perfil.html', perfis=perfis, sort=sort, order=order)


@app.route('/perfil/salvar', methods=['POST'])
@login_required
def salvar_perfil():
    id_perfil = request.form.get('id')
    nome      = request.form.get('nome', '').strip()
    nivel     = request.form.get('nivel') or None
    cor_bg    = request.form.get('cor_bg', '#e0e7ff')
    cor_texto = request.form.get('cor_texto', '#1e293b')

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            if id_perfil:
                cursor.execute("UPDATE perfil SET nome=%s, nivel=%s, cor_bg=%s, cor_texto=%s WHERE id=%s", (nome, nivel, cor_bg, cor_texto, id_perfil))
            else:
                cursor.execute("INSERT INTO perfil (nome, nivel, cor_bg, cor_texto) VALUES (%s, %s, %s, %s)", (nome, nivel, cor_bg, cor_texto))
    except Exception as e:
        print(f"Erro ao salvar perfil: {e}")
        return redirect('/perfil?erro=salvar')

    return redirect('/perfil?ok=salvo')


@app.route('/perfil/deletar/<int:id>')
@login_required
def deletar_perfil(id):
    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("DELETE FROM perfil WHERE id = %s", (id,))
    except Exception as e:
        print(f"Erro ao deletar perfil: {e}")
        return redirect('/perfil?erro=deletar')
    return redirect('/perfil?ok=deletado')


# ============================================================
# PRÊMIOS
# ============================================================

def _check_senha_eletronica(id_usuario, senha):
    """Retorna (True, None) se ok, ou (False, motivo) caso contrário."""
    with get_cursor() as (_, cursor):
        cursor.execute("SELECT senha_eletronica FROM usuarios WHERE id = %s", (id_usuario,))
        row = cursor.fetchone()
    if not row or not row['senha_eletronica']:
        return False, 'sem_permissao'
    if not check_password_hash(row['senha_eletronica'], senha):
        return False, 'senha_invalida'
    return True, None


def _check_permissao_premio(id_usuario, tipo):
    """tipo: 'incluir' ou 'autorizar'. Retorna True/False."""
    campo = 'pode_incluir' if tipo == 'incluir' else 'pode_autorizar'
    with get_cursor() as (_, cursor):
        cursor.execute(f"SELECT {campo} FROM premios_permissoes WHERE id_usuario = %s", (id_usuario,))
        row = cursor.fetchone()
    return bool(row and row[campo])


@app.route('/premios')
@login_required
@acesso_rotina_required('premios')
def premios():
    id_usuario    = session['usuario_id']
    filtro_status = request.args.get('status', '')
    order_by      = request.args.get('order_by', 'data_inclusao')
    order_dir     = request.args.get('order_dir', 'DESC')

    # Validar parâmetros de ordenação para evitar SQL injection
    colunas_validas = ['id', 'operador_nome', 'tipo', 'quantidade', 'valor', 'periodo', 'data', 'status', 'data_inclusao']
    if order_by not in colunas_validas:
        order_by = 'data_inclusao'
    if order_dir not in ['ASC', 'DESC']:
        order_dir = 'DESC'

    # Se clicar na mesma coluna, inverte a direção
    order_col_prefix = 'o.nome' if order_by == 'operador_nome' else f'p.{order_by}'

    with get_cursor() as (_, cursor):
        cursor.execute("""
            SELECT COALESCE(pp.pode_incluir, 0)   AS pode_incluir,
                   COALESCE(pp.pode_autorizar, 0) AS pode_autorizar
            FROM usuarios u
            LEFT JOIN premios_permissoes pp ON pp.id_usuario = u.id
            WHERE u.id = %s
        """, (id_usuario,))
        perms = cursor.fetchone() or {'pode_incluir': 0, 'pode_autorizar': 0}

        q = """
            SELECT p.*,
                   o.nome  AS operador_nome,
                   u.nome  AS unidade_nome,
                   ui.nome AS usuario_inclusao_nome,
                   ua.nome AS usuario_autorizacao_nome
            FROM premios p
            LEFT JOIN operadores o  ON o.id  = p.id_operadores
            LEFT JOIN unidades   u  ON u.id  = p.id_unidades_pagador
            LEFT JOIN usuarios   ui ON ui.id = p.id_usuarios
            LEFT JOIN usuarios   ua ON ua.id = p.id_usuarios_autorizador
        """
        params = []
        if filtro_status:
            q += " WHERE p.status = %s"
            params.append(filtro_status)
        q += f" ORDER BY {order_col_prefix} {order_dir}"
        cursor.execute(q, params)
        lista_premios = cursor.fetchall()

        cursor.execute("SELECT id, nome FROM operadores WHERE status='A' ORDER BY nome")
        operadores = cursor.fetchall()
        cursor.execute("SELECT id, nome FROM unidades ORDER BY nome")
        unidades = cursor.fetchall()

    return render_template('premios.html',
                           premios=lista_premios,
                           operadores=operadores,
                           unidades=unidades,
                           filtro_status=filtro_status,
                           order_by=order_by,
                           order_dir=order_dir,
                           perms=perms)


# ===== ENDPOINTS PARA CARREGAMENTO DINÂMICO DE PRÊMIOS =====

@app.route('/premios/operador/<int:id>')
@login_required
def premio_operador(id):
    with get_cursor() as (_, cursor):
        cursor.execute("SELECT id_perfil FROM operadores WHERE id = %s", (id,))
        row = cursor.fetchone()
    if not row:
        return jsonify({'erro': 'not_found'}), 404
    return jsonify({'id_perfil': row['id_perfil']})


@app.route('/premios/regras/<int:id_perfil>')
@login_required
def premio_regras(id_perfil):
    with get_cursor() as (_, cursor):
        cursor.execute("""
            SELECT id, quantidade, tipo, valor, periodo
            FROM premios_tabela
            WHERE id_perfil = %s OR id_perfil IS NULL
            ORDER BY tipo, periodo
        """, (id_perfil,))
        regras = cursor.fetchall()
    return jsonify({'regras': regras})


@app.route('/premios/regra/<int:id_regra>')
@login_required
def premio_regra(id_regra):
    with get_cursor() as (_, cursor):
        cursor.execute("""
            SELECT id, quantidade, tipo, valor, periodo
            FROM premios_tabela WHERE id = %s
        """, (id_regra,))
        regra = cursor.fetchone()
    if not regra:
        return jsonify({'erro': 'not_found'}), 404
    return jsonify(regra)


@app.route('/premios/json/<int:id>')
@login_required
def premio_json(id):
    with get_cursor() as (_, cursor):
        cursor.execute("SELECT * FROM premios WHERE id = %s", (id,))
        premio = cursor.fetchone()
        if not premio:
            return jsonify({'erro': 'not_found'}), 404
        cursor.execute("SELECT * FROM premios_rateio WHERE id_premios = %s", (id,))
        rateio = cursor.fetchall()

    p = dict(premio)
    for campo in ('data', 'data_inclusao', 'data_autorizacao', 'data_pagamento'):
        if p.get(campo):
            p[campo] = str(p[campo])
    return jsonify({'premio': p, 'rateio': rateio})


@app.route('/premios/salvar', methods=['POST'])
@login_required
def salvar_premio():
    id_usuario = session['usuario_id']
    id_premio  = request.form.get('id') or None

    if not _check_permissao_premio(id_usuario, 'incluir'):
        return redirect('/premios?erro=sem_permissao')

    if id_premio:
        with get_cursor() as (_, cursor):
            cursor.execute("SELECT status FROM premios WHERE id = %s", (id_premio,))
            row = cursor.fetchone()
        if not row or row['status'] != 'I':
            return redirect('/premios?erro=nao_editavel')

    ok, motivo = _check_senha_eletronica(id_usuario, request.form.get('senha_eletronica', ''))
    if not ok:
        return jsonify({'erro': motivo}), 400

    id_premios_tabela   = request.form.get('id_regra')
    id_operadores       = request.form.get('id_operadores')
    data                = request.form.get('data')
    id_unidades_pagador = request.form.get('id_unidades_pagador')

    # Validar data
    from datetime import datetime, date
    data_obj = datetime.strptime(data, '%Y-%m-%d').date()
    hoje = date.today()

    if data_obj > hoje:
        return jsonify({'erro': 'data_futura'}), 400

    if data_obj.weekday() == 6:  # 6 = domingo
        return jsonify({'erro': 'data_domingo'}), 400

    # Carrega dados da regra (valor, quantidade, tipo, período)
    with get_cursor() as (_, cursor):
        cursor.execute("""
            SELECT quantidade, tipo, valor, periodo
            FROM premios_tabela WHERE id = %s
        """, (id_premios_tabela,))
        regra = cursor.fetchone()

    if not regra:
        return jsonify({'erro': 'regra_nao_encontrada'}), 400

    tipo          = regra['tipo']
    valor         = Decimal(str(regra['valor']))
    quantidade    = int(regra['quantidade'])
    periodicidade = regra['periodo']

    unidade_ids  = request.form.getlist('id_unidade[]')
    qtd_unidades = [int(x or 0) for x in request.form.getlist('qtd_unidade[]')]

    pares = [(uid, qtd) for uid, qtd in zip(unidade_ids, qtd_unidades) if qtd > 0]
    if not pares:
        return jsonify({'erro': 'rateio_vazio'}), 400

    total_qtd = sum(q for _, q in pares)

    # Valida se rateio bate exatamente com quantidade da tabela
    if total_qtd != quantidade:
        return jsonify({'erro': 'rateio_incorreto', 'esperado': quantidade, 'recebido': total_qtd}), 400

    # Rateio proporcional com correção de arredondamento na última parcela
    valores_rateio = []
    acumulado = Decimal('0.00')
    for i, (_, qtd) in enumerate(pares):
        if i == len(pares) - 1:
            vr = valor - acumulado
        else:
            vr = (valor * Decimal(str(qtd)) / Decimal(str(total_qtd))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        acumulado += vr
        valores_rateio.append(vr)

    rateio_flag = 'S' if len(pares) > 1 else 'N'

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            if id_premio:
                cursor.execute("""
                    UPDATE premios
                    SET id_operadores=%s, tipo=%s, valor=%s, quantidade=%s,
                        periodicidade=%s, data=%s, id_unidades_pagador=%s,
                        rateio=%s, total_premio=%s, id_premios_tabela=%s
                    WHERE id=%s
                """, (id_operadores, tipo, float(valor), quantidade,
                      periodicidade, data, id_unidades_pagador,
                      rateio_flag, quantidade, id_premios_tabela, id_premio))
                cursor.execute("DELETE FROM premios_rateio WHERE id_premios = %s", (id_premio,))
            else:
                cursor.execute("""
                    INSERT INTO premios
                        (id_operadores, tipo, valor, quantidade, periodicidade, data,
                         id_unidades_pagador, status, rateio, total_premio, id_usuarios, id_premios_tabela)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,'I',%s,%s,%s,%s)
                """, (id_operadores, tipo, float(valor), quantidade,
                      periodicidade, data, id_unidades_pagador,
                      rateio_flag, quantidade, id_usuario, id_premios_tabela))
                id_premio = cursor.lastrowid

            for (uid, qtd), vr in zip(pares, valores_rateio):
                cursor.execute("""
                    INSERT INTO premios_rateio
                        (id_premios, id_unidades, quantidade, valor, id_unidades_pagador)
                    VALUES (%s,%s,%s,%s,%s)
                """, (id_premio, uid, qtd, float(vr), id_unidades_pagador))
    except Exception as e:
        import traceback
        print(f"Erro ao salvar prêmio: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'erro': 'salvar', 'detalhes': str(e)}), 500

    return jsonify({'ok': True})


@app.route('/premios/cancelar/<int:id>')
@login_required
def cancelar_premio(id):
    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("UPDATE premios SET status='C' WHERE id = %s", (id,))
    except Exception as e:
        print(f"Erro ao cancelar prêmio: {e}")
        return redirect('/premios?erro=cancelar')
    return redirect('/premios?ok=cancelado')


@app.route('/premios/autorizar', methods=['POST'])
@login_required
def autorizar_premio():
    id_usuario = session['usuario_id']
    id_premio  = request.form.get('id_premio')

    if not _check_permissao_premio(id_usuario, 'autorizar'):
        return redirect('/premios?erro=sem_permissao')

    ok, motivo = _check_senha_eletronica(id_usuario, request.form.get('senha_eletronica', ''))
    if not ok:
        return redirect(f'/premios?erro={motivo}')

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("""
                UPDATE premios
                SET status='A', data_autorizacao=NOW(), id_usuarios_autorizador=%s
                WHERE id=%s AND status='I'
            """, (id_usuario, id_premio))
    except Exception as e:
        print(f"Erro ao autorizar prêmio: {e}")
        return redirect('/premios?erro=autorizar')
    return redirect('/premios?ok=autorizado')


@app.route('/premios/pagar', methods=['POST'])
@login_required
def pagar_premio():
    id_usuario = session['usuario_id']
    id_premio  = request.form.get('id_premio')
    id_unidades_pagador = request.form.get('id_unidades_pagador_pag')

    if not _check_permissao_premio(id_usuario, 'autorizar'):
        return redirect('/premios?erro=sem_permissao')

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("""
                UPDATE premios SET status='P', data_pagamento=CURDATE(), id_unidades_pagador=%s
                WHERE id=%s AND status='A'
            """, (id_unidades_pagador, id_premio))
    except Exception as e:
        print(f"Erro ao registrar pagamento: {e}")
        return redirect('/premios?erro=pagar')
    return redirect('/premios?ok=pago')


@app.route('/premios/recibo/<int:id>')
@login_required
def recibo_premio(id):
    with get_cursor() as (_, cursor):
        cursor.execute("""
            SELECT p.*,
                   o.nome    AS operador_nome,
                   u.nome    AS unidade_nome,
                   u.cidade  AS unidade_cidade
            FROM premios p
            LEFT JOIN operadores o ON o.id = p.id_operadores
            LEFT JOIN unidades   u ON u.id = p.id_unidades_pagador
            WHERE p.id = %s
        """, (id,))
        premio = cursor.fetchone()
        if not premio:
            return redirect('/premios?erro=nao_encontrado')
        cursor.execute("""
            SELECT r.*, un.nome AS unidade_nome
            FROM premios_rateio r
            LEFT JOIN unidades un ON un.id = r.id_unidades
            WHERE r.id_premios = %s
        """, (id,))
        rateio = cursor.fetchall()

    data_impressao = datetime.now().strftime('%d/%m/%Y')
    return render_template('premios_recibo.html',
                           premio=premio,
                           rateio=rateio,
                           data_impressao=data_impressao)


# ===== TABELA DE PRÊMIOS (MANUTENÇÃO) =====

@app.route('/premios_tabela')
@login_required
@acesso_rotina_required('premios_tabela')
def premios_tabela():
    with get_cursor() as (_, cursor):
        cursor.execute("""
            SELECT p.*, pf.nome AS perfil_nome, pf.cor_bg, pf.cor_texto
            FROM premios_tabela p
            LEFT JOIN perfil pf ON pf.id = p.id_perfil
            ORDER BY p.periodo, p.tipo, p.valor
        """)
        lista = cursor.fetchall()
        cursor.execute("SELECT id, nome FROM perfil ORDER BY nome")
        perfis = cursor.fetchall()
    return render_template('premios_tabela.html', premios_tabela=lista, perfis=perfis)


@app.route('/premios_tabela/salvar', methods=['POST'])
@login_required
def salvar_premios_tabela():
    id_premio = request.form.get('id') or None
    quantidade = request.form.get('quantidade')
    tipo = request.form.get('tipo')
    valor = request.form.get('valor')
    descricao = request.form.get('descricao', '').strip()
    periodo = request.form.get('periodo')
    id_perfil = request.form.get('id_perfil') or None

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            if id_premio:
                cursor.execute("""
                    UPDATE premios_tabela
                    SET quantidade=%s, tipo=%s, valor=%s, descricao=%s, periodo=%s, id_perfil=%s
                    WHERE id=%s
                """, (quantidade, tipo, valor, descricao, periodo, id_perfil, id_premio))
            else:
                cursor.execute("""
                    INSERT INTO premios_tabela (quantidade, tipo, valor, descricao, periodo, id_perfil)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (quantidade, tipo, valor, descricao, periodo, id_perfil))
    except Exception as e:
        print(f"Erro ao salvar premiação: {e}")
        return redirect('/premios_tabela?erro=salvar')

    return redirect('/premios_tabela?ok=salvo')


@app.route('/premios_tabela/deletar/<int:id>')
@login_required
def deletar_premios_tabela(id):
    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("DELETE FROM premios_tabela WHERE id = %s", (id,))
    except Exception as e:
        print(f"Erro ao deletar premiação: {e}")
        return redirect('/premios_tabela?erro=deletar')
    return redirect('/premios_tabela?ok=deletado')


# ===== PERMISSÕES DE PRÊMIOS =====

@app.route('/premios/permissoes')
@login_required
@acesso_rotina_required('premios_permissoes')
def premios_permissoes():
    with get_cursor() as (_, cursor):
        # Usuários que JÁ têm registro de permissões
        cursor.execute("""
            SELECT u.id, u.nome, u.email,
                   pp.pode_incluir, pp.pode_autorizar,
                   CASE WHEN u.senha_eletronica IS NOT NULL
                             AND u.senha_eletronica != ''
                        THEN 1 ELSE 0 END AS tem_senha_el
            FROM premios_permissoes pp
            INNER JOIN usuarios u ON u.id = pp.id_usuario
            WHERE u.ativo = 'A'
            ORDER BY u.nome
        """)
        usuarios = cursor.fetchall()
        # Usuários ativos que AINDA NÃO têm permissões (para o modal "Novo")
        cursor.execute("""
            SELECT u.id, u.nome
            FROM usuarios u
            LEFT JOIN premios_permissoes pp ON pp.id_usuario = u.id
            WHERE u.ativo = 'A' AND pp.id IS NULL
            ORDER BY u.nome
        """)
        usuarios_sem_perm = cursor.fetchall()
    return render_template('premios_permissoes.html',
                           usuarios=usuarios,
                           usuarios_sem_perm=usuarios_sem_perm)


@app.route('/premios/permissoes/salvar', methods=['POST'])
@login_required
def salvar_premios_permissoes():
    print("=== INICIANDO salvar_premios_permissoes ===")
    id_usuario     = request.form.get('id_usuario')
    pode_incluir   = 1 if request.form.get('pode_incluir')   else 0
    pode_autorizar = 1 if request.form.get('pode_autorizar') else 0
    senha_antiga   = request.form.get('senha_antiga',   '').strip()
    senha_nova     = request.form.get('senha_nova',     '').strip()
    senha_confirma = request.form.get('senha_confirma', '').strip()
    print(f"id_usuario={id_usuario}, pode_incluir={pode_incluir}, pode_autorizar={pode_autorizar}")
    print(f"senha_nova={bool(senha_nova)}, senha_confirma={bool(senha_confirma)}")

    # Valida senhas ANTES de gravar qualquer coisa
    hash_novo = None
    if senha_nova:
        if senha_nova != senha_confirma:
            return redirect('/premios/permissoes?erro=senha_confirma')
        with get_cursor() as (_, cursor):
            cursor.execute("SELECT senha_eletronica FROM usuarios WHERE id = %s", (id_usuario,))
            row = cursor.fetchone()
        if row and row['senha_eletronica']:
            if not senha_antiga:
                return redirect('/premios/permissoes?erro=senha_antiga_obrigatoria')
            if not check_password_hash(row['senha_eletronica'], senha_antiga):
                return redirect('/premios/permissoes?erro=senha_antiga_incorreta')
        hash_novo = generate_password_hash(senha_nova)

    try:
        with get_cursor(dictionary=False) as (_, cursor):
            cursor.execute("""
                INSERT INTO premios_permissoes (id_usuario, pode_incluir, pode_autorizar)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE pode_incluir=%s, pode_autorizar=%s
            """, (id_usuario, pode_incluir, pode_autorizar, pode_incluir, pode_autorizar))
            if hash_novo:
                cursor.execute(
                    "UPDATE usuarios SET senha_eletronica=%s WHERE id=%s",
                    (hash_novo, id_usuario)
                )
    except Exception as e:
        import traceback
        print(f"ERRO DETALHADO ao salvar permissões:")
        print(f"Tipo: {type(e).__name__}")
        print(f"Mensagem: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return redirect('/premios/permissoes?erro=salvar')

    return redirect('/premios/permissoes?ok=salvo')


# ===== CONTROLE DE ACESSO ÀS ROTINAS =====

def verificar_acesso_alteracao(id_usuario, nome_rotina):
    """Verifica se o usuário tem acesso de ALTERAÇÃO (não apenas leitura)"""
    id_rotina = get_rotina_id(nome_rotina)
    if not id_rotina:
        return False
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("""
                SELECT acesso FROM rotinas_acesso ra
                JOIN perfil p ON p.id = ra.id_perfil
                JOIN usuarios u ON u.id_perfil = p.id
                WHERE u.id = %s AND ra.id_rotinas = %s
            """, (id_usuario, id_rotina))
            resultado = cursor.fetchone()
            return resultado and resultado['acesso'] == 'A'
    except Exception as e:
        print(f"[AVISO] Erro ao verificar acesso de alteração: {e}")
        return False


def verificar_acesso_rotina(id_usuario, id_rotina):
    """
    Verifica o acesso do usuário a uma rotina específica.
    Retorna: 'A' (Alteracao), 'L' (Leitura), None (Sem acesso)
    """
    try:
        with get_cursor() as (_, cursor):
            # Busca o perfil do usuário
            cursor.execute("SELECT id_perfil FROM usuarios WHERE id = %s", (id_usuario,))
            usuario = cursor.fetchone()

            if not usuario or not usuario['id_perfil']:
                print(f"[AVISO] Usuario {id_usuario} sem perfil definido")
                return None

            id_perfil = usuario['id_perfil']

            # Busca acesso específico para essa rotina
            cursor.execute("""
                SELECT acesso FROM rotinas_acesso
                WHERE id_perfil = %s AND id_rotinas = %s
            """, (id_perfil, id_rotina))

            result = cursor.fetchone()
            acesso = result['acesso'] if result else None
            print(f"[OK] Acesso do usuario {id_usuario} rotina {id_rotina}: {acesso}")
            return acesso
    except Exception as e:
        print(f"[AVISO] Erro ao verificar acesso rotina {id_rotina}: {e}")
        return None


def obter_rotinas_acesso_usuario(id_usuario):
    """
    Obtém lista de IDs de rotinas que o usuário tem acesso (verde ou amarelo).
    Se houver erro ou sem dados, retorna lista vazia (fallback será permitir acesso).
    """
    try:
        with get_cursor() as (_, cursor):
            # Busca rotinas do usuário via seu perfil
            cursor.execute("""
                SELECT DISTINCT ra.id_rotinas
                FROM rotinas_acesso ra
                JOIN perfil p ON p.id = ra.id_perfil
                JOIN usuarios u ON u.id_perfil = p.id
                WHERE u.id = %s AND ra.acesso IN ('A', 'L')
            """, (id_usuario,))
            resultado = [row['id_rotinas'] for row in cursor.fetchall()]
            print(f"[OK] Rotinas do usuario {id_usuario}: {resultado}")
            return resultado
    except Exception as e:
        print(f"[AVISO] Erro ao obter rotinas (banco vazio ou tabela nao existe): {e}")
        return []  # Retorna vazio, menu mostrará tudo


@app.route('/rotinas/permissoes')
@login_required
def rotinas_permissoes():
    """Página de gerenciamento de permissões de rotinas por perfil"""
    try:
        # Parâmetros de ordenação
        sort = request.args.get('sort', 'rotina')
        order = request.args.get('order', 'asc')
        if sort not in ('rotina', 'descricao'):
            sort = 'rotina'
        if order not in ('asc', 'desc'):
            order = 'asc'

        with get_cursor() as (_, cursor):
            # Busca todos os perfis
            try:
                print("[TENTANDO] SELECT id, nome FROM perfil")
                cursor.execute("SELECT id, nome FROM perfil ORDER BY nome")
                perfis = cursor.fetchall()
                print(f"[OK] Perfis carregados: {len(perfis)}")
            except Exception as e_perfis:
                print(f"[ERRO PERFIS] {e_perfis}")
                raise

            # Busca TODAS as rotinas com ordenação
            try:
                print("[TENTANDO] SELECT * FROM rotinas")
                cursor.execute(f"SELECT * FROM rotinas ORDER BY {sort} {order}")
                rotinas_raw = cursor.fetchall()

                # Debug: mostra as colunas da tabela rotinas
                if rotinas_raw:
                    colunas = list(rotinas_raw[0].keys())
                    print(f"[DEBUG] Colunas da tabela rotinas: {colunas}")

                # Converte para formato esperado (id, rotina, descricao)
                rotinas = []
                for r in rotinas_raw:
                    rotinas.append({
                        'id': r.get('id'),
                        'nome': r.get('rotina') or '',
                        'descricao': r.get('descricao') or ''
                    })

                print(f"[OK] Rotinas carregadas: {len(rotinas)}")
            except Exception as e_rotinas:
                print(f"[ERRO ROTINAS] {e_rotinas}")
                import traceback
                traceback.print_exc()
                raise

            # Busca permissões (por perfil, se houver seleção)
            id_perfil = request.args.get('id_perfil')
            permissoes = {}
            if id_perfil:
                try:
                    print(f"[TENTANDO] SELECT permissoes para perfil {id_perfil}")
                    cursor.execute("""
                        SELECT id_rotinas, acesso
                        FROM rotinas_acesso
                        WHERE id_perfil = %s
                    """, (id_perfil,))
                    for row in cursor.fetchall():
                        permissoes[row['id_rotinas']] = row['acesso']
                    print(f"[OK] Permissoes do perfil {id_perfil}: {len(permissoes)}")
                except Exception as e_perm:
                    print(f"[ERRO PERMISSOES] {e_perm}")
                    raise

        return render_template(
            'rotinas_permissoes.html',
            perfis=perfis,
            rotinas=rotinas,
            permissoes=permissoes,
            perfil_selecionado=int(id_perfil) if id_perfil else None,
            sort=sort,
            order=order
        )
    except Exception as e:
        print(f"[ERRO GERAL] Erro ao carregar rotinas/permissoes: {e}")
        import traceback
        traceback.print_exc()
        return render_template(
            'rotinas_permissoes.html',
            perfis=[],
            rotinas=[],
            permissoes={},
            perfil_selecionado=None,
            sort=request.args.get('sort', 'rotina'),
            order=request.args.get('order', 'asc'),
            erro=f"Erro ao carregar dados: {str(e)}"
        )


@app.route('/rotinas/permissoes/salvar', methods=['POST'])
@login_required
def salvar_rotinas_permissoes():
    """Salva permissões de rotinas para um perfil"""
    try:
        id_perfil = request.form.get('id_perfil')

        with get_cursor(dictionary=False) as (conn, cursor):
            # Processa cada rotina
            for key in request.form:
                if key.startswith('acesso_'):
                    id_rotina = key.replace('acesso_', '')
                    acesso = request.form.get(key)

                    # Verifica se já existe
                    cursor.execute(
                        "SELECT id FROM rotinas_acesso WHERE id_perfil = %s AND id_rotinas = %s",
                        (id_perfil, id_rotina)
                    )
                    existe = cursor.fetchone()

                    if acesso == 'V':  # Vermelho - sem acesso
                        if existe:
                            cursor.execute(
                                "DELETE FROM rotinas_acesso WHERE id_perfil = %s AND id_rotinas = %s",
                                (id_perfil, id_rotina)
                            )
                    else:  # Verde ('A') ou Amarelo ('L')
                        valor_acesso = 'A' if acesso == 'G' else 'L'
                        if existe:
                            cursor.execute(
                                "UPDATE rotinas_acesso SET acesso = %s WHERE id_perfil = %s AND id_rotinas = %s",
                                (valor_acesso, id_perfil, id_rotina)
                            )
                        else:
                            cursor.execute(
                                "INSERT INTO rotinas_acesso (id_perfil, id_rotinas, acesso) VALUES (%s, %s, %s)",
                                (id_perfil, id_rotina, valor_acesso)
                            )
            conn.commit()

        # Atualizar sessão se o usuário logado é do perfil editado
        if 'usuario_id' in session:
            with get_cursor() as (_, cursor):
                cursor.execute("SELECT id_perfil FROM usuarios WHERE id = %s", (session['usuario_id'],))
                resultado = cursor.fetchone()
                if resultado and str(resultado['id_perfil']) == str(id_perfil):
                    # Recarrega as rotinas na sessão
                    rotinas_acesso = obter_rotinas_acesso_usuario(session['usuario_id'])
                    session['rotinas_acesso'] = rotinas_acesso
                    print(f"[OK] Sessão do usuário {session['usuario_id']} atualizada: {rotinas_acesso}")
    except Exception as e:
        print(f"Erro ao salvar permissões: {e}")
        return redirect(f'/rotinas/permissoes?id_perfil={id_perfil}&erro=salvar')

    return redirect(f'/rotinas/permissoes?id_perfil={id_perfil}&ok=salvo')


# 🏢 UNIDADES
@app.route('/unidades')
@login_required
def unidades():
    """Lista todas as unidades"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("SELECT * FROM unidades ORDER BY nome")
            unidades_list = cursor.fetchall()

        # Converter timedelta para string hh:mm
        for u in unidades_list:
            for campo in ['hora_inicio', 'hora_final', 'hora_inicio_sab', 'hora_final_sab']:
                if u.get(campo):
                    total_seconds = int(u[campo].total_seconds())
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                    u[campo] = f"{hours:02d}:{minutes:02d}"

        return render_template('unidades.html', unidades=unidades_list)
    except Exception as e:
        print(f"[ERRO] Listar unidades: {e}")
        return render_template('unidades.html', unidades=[], erro="Erro ao carregar unidades")


@app.route('/unidades/salvar', methods=['POST'])
@login_required
def salvar_unidade():
    """Salvar/editar unidade"""
    try:
        id_unidade = request.form.get('id', '').strip()
        nome = request.form.get('nome', '').strip()
        endereco = request.form.get('endereco', '').strip()
        observacao = request.form.get('observacao', '').strip()
        telefone = request.form.get('telefone', '').strip()
        bairro = request.form.get('bairro', '').strip()
        cidade = request.form.get('cidade', '').strip()
        sigla = request.form.get('sigla', '').strip()
        hora_inicio = request.form.get('hora_inicio', '').strip()
        hora_final = request.form.get('hora_final', '').strip()
        intervalo = request.form.get('intervalo', '0').strip()
        agendamento_quantidade = request.form.get('agendamento_quantidade', '0').strip()
        hora_inicio_sab = request.form.get('hora_inicio_sab', '').strip()
        hora_final_sab = request.form.get('hora_final_sab', '').strip()
        cor_bg = request.form.get('cor_bg', '#e0e7ff').strip()
        cor_texto = request.form.get('cor_texto', '#4f46e5').strip()

        if not nome or not sigla:
            return redirect('/unidades?erro=campos_obrigatorios')

        with get_cursor() as (_, cursor):
            if id_unidade:
                # Editar
                cursor.execute("""
                    UPDATE unidades SET
                        nome=%s, endereco=%s, observacao=%s, telefone=%s,
                        bairro=%s, cidade=%s, sigla=%s, hora_inicio=%s,
                        hora_final=%s, intervalo=%s, agendamento_quantidade=%s,
                        hora_inicio_sab=%s, hora_final_sab=%s, cor_bg=%s, cor_texto=%s
                    WHERE id=%s
                """, (nome, endereco, observacao, telefone, bairro, cidade,
                      sigla, hora_inicio, hora_final, intervalo, agendamento_quantidade,
                      hora_inicio_sab, hora_final_sab, cor_bg, cor_texto, id_unidade))
            else:
                # Criar
                cursor.execute("""
                    INSERT INTO unidades
                    (nome, endereco, observacao, telefone, bairro, cidade, sigla,
                     hora_inicio, hora_final, intervalo, agendamento_quantidade,
                     hora_inicio_sab, hora_final_sab, cor_bg, cor_texto)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (nome, endereco, observacao, telefone, bairro, cidade, sigla,
                      hora_inicio, hora_final, intervalo, agendamento_quantidade,
                      hora_inicio_sab, hora_final_sab, cor_bg, cor_texto))

        return redirect('/unidades?ok=salvo')

    except Exception as e:
        print(f"[ERRO] Salvar unidade: {e}")
        return redirect('/unidades?erro=salvar')


@app.route('/unidades/deletar/<int:id>', methods=['POST'])
@login_required
def deletar_unidade(id):
    """Deletar unidade"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("DELETE FROM unidades WHERE id=%s", (id,))
        return redirect('/unidades?ok=deletado')
    except Exception as e:
        print(f"[ERRO] Deletar unidade: {e}")
        return redirect('/unidades?erro=deletar')


# 🚫 AGENDAMENTO BLOQUEIO
@app.route('/agendamento_bloqueio')
@login_required
def agendamento_bloqueio():
    """Lista bloqueios de agendamento"""
    try:
        sort = request.args.get('sort', 'unidade')
        order = request.args.get('order', 'asc').lower()

        # Validar order (apenas asc ou desc)
        if order not in ('asc', 'desc'):
            order = 'asc'

        # Montar ORDER BY dinamicamente
        ordem_sql = ""
        if sort == 'unidade':
            ordem_sql = f"u.nome {order}, ab.data_inicio asc, ab.hora_inicio asc"
        elif sort == 'data_inicio':
            ordem_sql = f"ab.data_inicio {order}, ab.hora_inicio asc"
        elif sort == 'data_final':
            ordem_sql = f"ab.data_final {order}"
        elif sort == 'motivo':
            ordem_sql = f"ab.motivo {order}"
        else:
            ordem_sql = "ab.data_inicio desc, ab.hora_inicio asc"

        with get_cursor() as (_, cursor):
            cursor.execute(f"""
                SELECT ab.*, u.nome as unidade_nome, u.sigla, u.cor_bg, u.cor_texto
                FROM agendamento_bloqueio ab
                LEFT JOIN unidades u ON ab.unidades_id = u.id
                ORDER BY {ordem_sql}
            """)
            bloqueios = cursor.fetchall()

            # Converter timedelta para string hh:mm
            for b in bloqueios:
                if b.get('hora_inicio'):
                    total_seconds = int(b['hora_inicio'].total_seconds())
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                    b['hora_inicio'] = f"{hours:02d}:{minutes:02d}"
                if b.get('hora_final'):
                    total_seconds = int(b['hora_final'].total_seconds())
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                    b['hora_final'] = f"{hours:02d}:{minutes:02d}"

            # Obter lista de unidades para o select
            cursor.execute("SELECT id, nome, sigla FROM unidades ORDER BY nome")
            unidades_list = cursor.fetchall()

        return render_template('agendamento_bloqueio.html', bloqueios=bloqueios, unidades=unidades_list, sort=sort, order=order)
    except Exception as e:
        print(f"[ERRO] Listar bloqueios: {e}")
        return render_template('agendamento_bloqueio.html', bloqueios=[], unidades=[], erro="Erro ao carregar bloqueios")


@app.route('/agendamento_bloqueio/salvar', methods=['POST'])
@login_required
@acesso_alteracao_required('agendamento_block')
def salvar_bloqueio():
    """Salvar/editar bloqueio de agendamento"""
    try:
        id_bloqueio = request.form.get('id', '').strip()
        data_inicio = request.form.get('data_inicio', '').strip()
        data_final = request.form.get('data_final', '').strip()
        hora_inicio = request.form.get('hora_inicio', '').strip()
        hora_final = request.form.get('hora_final', '').strip()
        unidades_id = request.form.get('unidades_id', '').strip()
        motivo = request.form.get('motivo', '').strip()

        if not data_inicio or not data_final or not unidades_id:
            return redirect('/agendamento_bloqueio?erro=campos_obrigatorios')

        with get_cursor() as (_, cursor):
            if id_bloqueio:
                # Editar
                cursor.execute("""
                    UPDATE agendamento_bloqueio SET
                        data_inicio=%s, data_final=%s, hora_inicio=%s,
                        hora_final=%s, unidades_id=%s, motivo=%s
                    WHERE id=%s
                """, (data_inicio, data_final, hora_inicio or None,
                      hora_final or None, unidades_id, motivo, id_bloqueio))
            else:
                # Criar
                cursor.execute("""
                    INSERT INTO agendamento_bloqueio
                    (data_inicio, data_final, hora_inicio, hora_final, unidades_id, motivo)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (data_inicio, data_final, hora_inicio or None,
                      hora_final or None, unidades_id, motivo))

        return redirect('/agendamento_bloqueio?ok=salvo')

    except Exception as e:
        print(f"[ERRO] Salvar bloqueio: {e}")
        return redirect('/agendamento_bloqueio?erro=salvar')


@app.route('/agendamento_bloqueio/deletar/<int:id>', methods=['POST'])
@login_required
@acesso_alteracao_required('agendamento_block')
def deletar_bloqueio(id):
    """Deletar bloqueio de agendamento"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("DELETE FROM agendamento_bloqueio WHERE id=%s", (id,))
        return redirect('/agendamento_bloqueio?ok=deletado')
    except Exception as e:
        print(f"[ERRO] Deletar bloqueio: {e}")
        return redirect('/agendamento_bloqueio?erro=deletar')


# 📅 AGENDA VISUAL (Agendamento de Visitas)
@app.route('/agenda_visual')
@login_required
@acesso_alteracao_required('agendamento')
def agenda_visual():
    """Tela visual de agendamento de visitas"""
    from datetime import datetime, timedelta

    try:
        # Obter unidades e operadores
        with get_cursor() as (_, cursor):
            cursor.execute("SELECT id, nome, sigla, intervalo, hora_inicio, hora_final, hora_inicio_sab, hora_final_sab FROM unidades ORDER BY nome")
            unidades_list = cursor.fetchall()
            cursor.execute("SELECT id, nome FROM operadores ORDER BY nome")
            operadores_list = cursor.fetchall()

            # Buscar operador associado ao usuário logado
            usuario_id = session.get('usuario_id')
            operador_usuario = None
            if usuario_id:
                cursor.execute("SELECT id FROM operadores WHERE id_usuarios=%s LIMIT 1", (usuario_id,))
                resultado = cursor.fetchone()
                if resultado:
                    operador_usuario = resultado['id']

        return render_template('agenda_visual.html', unidades=unidades_list, operadores=operadores_list,
                             operador_usuario=operador_usuario, data_padrao=datetime.now().strftime('%Y-%m-%d'))
    except Exception as e:
        print(f"[ERRO] Agenda visual: {e}")
        return render_template('agenda_visual.html', unidades=[], operadores=[], erro="Erro ao carregar agenda")


@app.route('/api/horarios', methods=['GET'])
@login_required
@acesso_alteracao_required('agendamento')
def api_horarios():
    """API para obter horários e agendamentos de uma unidade/data"""
    from datetime import datetime, timedelta, time

    try:
        unidade_id = request.args.get('unidade_id')
        data = request.args.get('data')

        if not unidade_id or not data:
            return jsonify({'erro': 'Parâmetros inválidos'}), 400

        data_obj = datetime.strptime(data, '%Y-%m-%d').date()
        dia_semana = data_obj.weekday()  # 0=seg, 5=sab, 6=dom
        eh_sabado = dia_semana == 5
        eh_domingo = dia_semana == 6

        # Se for domingo, retornar lista vazia
        if eh_domingo:
            return jsonify({'horarios': []}), 200

        with get_cursor() as (_, cursor):
            # Obter info da unidade
            cursor.execute("""
                SELECT intervalo, hora_inicio, hora_final, hora_inicio_sab, hora_final_sab
                FROM unidades WHERE id=%s
            """, (unidade_id,))
            unidade = cursor.fetchone()

            if not unidade:
                return jsonify({'erro': 'Unidade não encontrada'}), 404

            # Determinar horários
            if eh_sabado:
                hora_inicio = unidade['hora_inicio_sab']
                hora_final = unidade['hora_final_sab']
            else:
                hora_inicio = unidade['hora_inicio']
                hora_final = unidade['hora_final']

            # Converter timedelta para time object se necessário
            def timedelta_para_time(td):
                if isinstance(td, timedelta):
                    total_seconds = int(td.total_seconds())
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                    return time(hours, minutes)
                return td

            # Gerar slots de horários
            horarios = []
            if hora_inicio and hora_final:
                hora_inicio = timedelta_para_time(hora_inicio)
                hora_final = timedelta_para_time(hora_final)
                h_inicio = datetime.combine(data_obj, hora_inicio)
                h_final = datetime.combine(data_obj, hora_final)
                intervalo_min = unidade['intervalo'] or 30

                atual = h_inicio
                while atual < h_final:
                    horarios.append(atual.strftime('%H:%M'))
                    atual += timedelta(minutes=intervalo_min)

            # Obter agendamentos do dia
            cursor.execute("""
                SELECT id, hora, nome, telefone
                FROM agendamento
                WHERE unidades_id=%s AND data=%s
                ORDER BY hora
            """, (unidade_id, data))
            agendamentos = cursor.fetchall()

            # Obter bloqueios
            cursor.execute("""
                SELECT * FROM agendamento_bloqueio
                WHERE unidades_id=%s
                AND %s BETWEEN data_inicio AND data_final
            """, (unidade_id, data))
            bloqueios = cursor.fetchall()

            # Montar resposta
            resultado = []
            for hora in horarios:
                slot = {
                    'hora': hora,
                    'status': 'livre',
                    'cliente_nome': None,
                    'cliente_telefone': None,
                    'agendamentos': 0
                }

                # Verificar agendamentos nesse horário
                agendados_nesse_horario = [a for a in agendamentos if str(a['hora']) == hora]
                slot['agendamentos'] = len(agendados_nesse_horario)

                # Verificar limite
                if slot['agendamentos'] > 0:
                    slot['status'] = 'ocupado'
                    if agendados_nesse_horario:
                        primeiro = agendados_nesse_horario[0]
                        slot['cliente_nome'] = primeiro.get('nome', 'Cliente')
                        slot['cliente_telefone'] = primeiro.get('telefone', '')

                # Verificar bloqueios
                for bloqueio in bloqueios:
                    hora_obj = datetime.strptime(hora, '%H:%M').time()

                    # Se o bloqueio tem horários específicos
                    if bloqueio['hora_inicio'] and bloqueio['hora_final']:
                        h_inicio_bloqueio = timedelta_para_time(bloqueio['hora_inicio'])
                        h_final_bloqueio = timedelta_para_time(bloqueio['hora_final'])
                        if h_inicio_bloqueio <= hora_obj < h_final_bloqueio:
                            slot['status'] = 'bloqueado'
                            slot['motivo'] = bloqueio.get('motivo', 'Bloqueado')
                    else:
                        # Bloqueio de dia completo
                        slot['status'] = 'bloqueado'
                        slot['motivo'] = bloqueio.get('motivo', 'Dia bloqueado')

                resultado.append(slot)

            return jsonify({'horarios': resultado}), 200

    except Exception as e:
        print(f"[ERRO] API horários: {e}")
        return jsonify({'erro': str(e)}), 500


# 💬 MENSAGENS WHATSAPP
@app.route('/mensagens')
@login_required
def mensagens():
    """Lista mensagens recebidas do WhatsApp"""
    try:
        filtro_lida = request.args.get('lida', '')
        filtro_unidade = request.args.get('unidade', '')
        sort = request.args.get('sort', 'data_recebida')
        order = request.args.get('order', 'desc')

        if sort not in ('data_recebida', 'nome_remetente', 'numero_remetente'):
            sort = 'data_recebida'
        if order not in ('asc', 'desc'):
            order = 'desc'

        with get_cursor() as (_, cursor):
            query = """
                SELECT m.*, u.nome as unidade_nome, u.sigla, o.nome as operador_nome
                FROM mensagens_whatsapp m
                LEFT JOIN unidades u ON m.id_unidade = u.id
                LEFT JOIN operadores o ON m.id_operador = o.id
                WHERE 1=1
            """
            params = []

            if filtro_lida:
                query += " AND m.lida = %s"
                params.append(1 if filtro_lida == 'lida' else 0)

            if filtro_unidade:
                query += " AND m.id_unidade = %s"
                params.append(filtro_unidade)

            query += f" ORDER BY m.{sort} {order}"

            cursor.execute(query, params)
            mensagens_list = cursor.fetchall()

            # Contagens para resumo
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN lida = 0 THEN 1 ELSE 0 END) as nao_lidas,
                    SUM(CASE WHEN lida = 1 THEN 1 ELSE 0 END) as lidas
                FROM mensagens_whatsapp
            """)
            resumo = cursor.fetchone()

            cursor.execute("SELECT id, nome FROM unidades ORDER BY nome")
            unidades_list = cursor.fetchall()

        return render_template('mensagens.html',
                             mensagens=mensagens_list,
                             unidades=unidades_list,
                             filtro_lida=filtro_lida,
                             filtro_unidade=filtro_unidade,
                             sort=sort,
                             order=order,
                             resumo=resumo)
    except Exception as e:
        print(f"[ERRO] Listar mensagens: {e}")
        return render_template('mensagens.html', mensagens=[], unidades=[], erro="Erro ao carregar mensagens")


@app.route('/mensagens/<int:id>', methods=['GET'])
@login_required
def visualizar_mensagem(id):
    """Visualiza detalhes de uma mensagem e marca como lida"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("""
                SELECT m.*, u.nome as unidade_nome, o.nome as operador_nome, us.nome as usuario_resposta_nome
                FROM mensagens_whatsapp m
                LEFT JOIN unidades u ON m.id_unidade = u.id
                LEFT JOIN operadores o ON m.id_operador = o.id
                LEFT JOIN usuarios us ON m.id_usuario_resposta = us.id
                WHERE m.id = %s
            """, (id,))
            mensagem = cursor.fetchone()

            if not mensagem:
                return redirect('/mensagens?erro=nao_encontrada')

            # Marcar como lida
            if mensagem['lida'] == 0:
                cursor.execute("""
                    UPDATE mensagens_whatsapp SET lida=1, data_leitura=NOW() WHERE id=%s
                """, (id,))

        return render_template('mensagem_detalhes.html', mensagem=mensagem)
    except Exception as e:
        print(f"[ERRO] Visualizar mensagem: {e}")
        return redirect('/mensagens?erro=carregar')


@app.route('/mensagens/<int:id>/responder', methods=['POST'])
@login_required
def responder_mensagem(id):
    """Salva resposta para uma mensagem do WhatsApp"""
    try:
        resposta = request.form.get('resposta', '').strip()
        id_usuario = session['usuario_id']

        if not resposta:
            return redirect(f'/mensagens/{id}?erro=resposta_vazia')

        with get_cursor() as (_, cursor):
            cursor.execute("""
                UPDATE mensagens_whatsapp
                SET resposta=%s, data_resposta=NOW(), id_usuario_resposta=%s
                WHERE id=%s
            """, (resposta, id_usuario, id))

        return redirect(f'/mensagens/{id}?ok=respondida')
    except Exception as e:
        print(f"[ERRO] Responder mensagem: {e}")
        return redirect(f'/mensagens/{id}?erro=responder')


@app.route('/api/webhook/whatsapp', methods=['POST'])
def webhook_whatsapp():
    """
    Webhook para receber mensagens do WhatsApp
    Integre com sua API de WhatsApp (Twilio, WhatsApp Business API, etc)

    Estrutura esperada do JSON:
    {
        "numero_remetente": "5511999999999",
        "nome_remetente": "João Silva",
        "mensagem": "Olá, gostaria de agendar uma visita",
        "tipo_mensagem": "texto",
        "id_whatsapp_api": "wamid.xxx",
        "id_operador": 1,  # opcional
        "id_unidade": 1    # opcional
    }
    """
    try:
        dados = request.get_json()

        if not dados or 'numero_remetente' not in dados or 'mensagem' not in dados:
            return jsonify({'erro': 'Dados inválidos'}), 400

        with get_cursor() as (_, cursor):
            cursor.execute("""
                INSERT INTO mensagens_whatsapp
                (numero_remetente, nome_remetente, mensagem, tipo_mensagem, id_whatsapp_api, id_operador, id_unidade)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                dados['numero_remetente'],
                dados.get('nome_remetente'),
                dados['mensagem'],
                dados.get('tipo_mensagem', 'texto'),
                dados.get('id_whatsapp_api'),
                dados.get('id_operador'),
                dados.get('id_unidade')
            ))

        return jsonify({'status': 'ok'}), 200

    except Exception as e:
        print(f"[ERRO] Webhook WhatsApp: {e}")
        return jsonify({'erro': str(e)}), 500


# 📊 DASHBOARD VENDEDORES
@app.route('/dashboard-vendedores')
@login_required
def dashboard_vendedores():
    """Dashboard com ranking de unidades e vendedores a partir da tabela ranking"""
    try:
        from datetime import datetime, date
        from calendar import monthrange

        # Pegar mês e ano do parâmetro ou usar mês atual
        mes = request.args.get('mes', datetime.now().month)
        ano = request.args.get('ano', datetime.now().year)

        try:
            mes = int(mes)
            ano = int(ano)
        except:
            mes = datetime.now().month
            ano = datetime.now().year

        # Calcular dias do mês e dias restantes
        ultima_dia_mes = monthrange(ano, mes)[1]
        dia_atual = date.today().day if date.today().month == mes and date.today().year == ano else ultima_dia_mes
        dias_restantes = ultima_dia_mes - dia_atual

        with get_cursor() as (_, cursor):
            # RANKING DE UNIDADES
            cursor.execute("""
                SELECT
                    u.id,
                    u.sigla,
                    u.nome as unidade_nome,
                    SUM(r.visitas) as total_visitas,
                    SUM(r.matriculas) as total_matriculas,
                    COUNT(DISTINCT r.data) as dias_cadastrados,
                    ROUND(SUM(r.matriculas) / SUM(r.visitas) * 100, 2) as conversao_pct,
                    ROUND(SUM(r.visitas) / COUNT(DISTINCT r.data), 1) as media_diaria_visitas,
                    ROUND(SUM(r.matriculas) / COUNT(DISTINCT r.data), 1) as media_diaria_matriculas
                FROM ranking r
                LEFT JOIN unidades u ON r.id_unidades = u.id
                WHERE MONTH(r.data) = %s AND YEAR(r.data) = %s
                GROUP BY u.id, u.sigla, u.nome
                ORDER BY total_matriculas DESC, total_visitas DESC
            """, (mes, ano))

            ranking_unidades = cursor.fetchall()

            # Adicionar projeção para cada unidade
            for unidade in ranking_unidades:
                projecao_visitas = int((unidade['media_diaria_visitas'] * dias_restantes) + unidade['total_visitas'])
                projecao_matriculas = int((unidade['media_diaria_matriculas'] * dias_restantes) + unidade['total_matriculas'])
                unidade['projecao_visitas'] = projecao_visitas
                unidade['projecao_matriculas'] = projecao_matriculas

            # RANKING DE VENDEDORES
            cursor.execute("""
                SELECT
                    v.id,
                    v.nome as vendedor_nome,
                    SUM(r.visitas) as total_visitas,
                    SUM(r.matriculas) as total_matriculas,
                    ROUND(SUM(r.matriculas) / SUM(r.visitas) * 100, 2) as conversao_pct
                FROM ranking r
                LEFT JOIN vendedores v ON r.id_vendedores = v.id
                WHERE MONTH(r.data) = %s AND YEAR(r.data) = %s
                GROUP BY v.id, v.nome
                ORDER BY total_matriculas DESC, total_visitas DESC
            """, (mes, ano))

            ranking_vendedores = cursor.fetchall()

            # Calcular totais gerais
            cursor.execute("""
                SELECT
                    SUM(visitas) as total_visitas,
                    SUM(matriculas) as total_matriculas,
                    COUNT(DISTINCT id_unidades) as total_unidades,
                    COUNT(DISTINCT id_vendedores) as total_vendedores,
                    COUNT(DISTINCT data) as dias_cadastrados
                FROM ranking
                WHERE MONTH(data) = %s AND YEAR(data) = %s
            """, (mes, ano))

            totais = cursor.fetchone()
            if totais and totais['total_visitas'] and totais['total_matriculas']:
                totais['conversao_pct'] = round(totais['total_matriculas'] / totais['total_visitas'] * 100, 2)
                totais['visitas_por_matricula'] = round(totais['total_visitas'] / totais['total_matriculas'], 2)
            else:
                totais = {
                    'total_visitas': 0,
                    'total_matriculas': 0,
                    'total_unidades': 0,
                    'total_vendedores': 0,
                    'dias_cadastrados': 0,
                    'conversao_pct': 0,
                    'visitas_por_matricula': 0
                }

        return render_template('dashboard_vendedores.html',
                             ranking_unidades=ranking_unidades,
                             ranking_vendedores=ranking_vendedores,
                             totais=totais,
                             mes=mes,
                             ano=ano,
                             dias_restantes=dias_restantes,
                             mes_nome=datetime(ano, mes, 1).strftime('%B de %Y'))
    except Exception as e:
        print(f"[ERRO] Dashboard vendedores: {e}")
        return render_template('dashboard_vendedores.html',
                             ranking_unidades=[],
                             ranking_vendedores=[],
                             totais={},
                             erro="Erro ao carregar dashboard")


# 📋 MATRÍCULAS
@app.route('/matriculas')
@login_required
def matriculas():
    """Lista matrículas com filtro por mês/ano"""
    try:
        from datetime import datetime

        # Pegar mês e ano do parâmetro ou usar mês/ano atual
        mes = request.args.get('mes', datetime.now().month)
        ano = request.args.get('ano', datetime.now().year)

        try:
            mes = int(mes)
            ano = int(ano)
        except:
            mes = datetime.now().month
            ano = datetime.now().year

        with get_cursor() as (_, cursor):
            # Buscar matrículas do mês/ano especificado
            cursor.execute("""
                SELECT m.*, v.nome as vendedor_nome, u.nome as unidade_nome, u.sigla
                FROM matriculas m
                LEFT JOIN vendedores v ON m.id_vendedores = v.id
                LEFT JOIN unidades u ON m.id_unidades = u.id
                WHERE m.data IS NOT NULL
                    AND MONTH(m.data) = %s
                    AND YEAR(m.data) = %s
                ORDER BY m.data DESC
            """, (mes, ano))
            matriculas_list = cursor.fetchall()

            # Buscar vendedores com suas unidades
            cursor.execute("""
                SELECT v.id, v.nome, v.id_unidades, u.nome as unidade_nome
                FROM vendedores v
                LEFT JOIN unidades u ON v.id_unidades = u.id
                ORDER BY v.nome
            """)
            vendedores_list = cursor.fetchall()

            cursor.execute("SELECT id, nome, sigla FROM unidades ORDER BY nome")
            unidades_list = cursor.fetchall()

        # Gerar nome do mês
        mes_nome = datetime(ano, mes, 1).strftime('%B de %Y')

        return render_template('matriculas.html',
                             matriculas=matriculas_list,
                             vendedores_list=vendedores_list,
                             unidades_list=unidades_list,
                             mes=mes,
                             ano=ano,
                             mes_nome=mes_nome)
    except Exception as e:
        print(f"[ERRO] Listar matrículas: {e}")
        return render_template('matriculas.html', matriculas=[], erro="Erro ao carregar matrículas")


@app.route('/matriculas/salvar', methods=['POST'])
@login_required
def salvar_matricula():
    """Salvar/editar matrícula"""
    try:
        id_matricula = request.form.get('id', '').strip()
        data = request.form.get('data', '').strip()
        valor_matricula = request.form.get('valor_matricula', '').strip()
        valor_parcela = request.form.get('valor_parcela', '').strip()
        qtd_parcelas = request.form.get('qtd_parcelas', '').strip()
        id_vendedores = request.form.get('id_vendedores', '').strip()
        id_unidades = request.form.get('id_unidades', '').strip()
        cliente_nome = request.form.get('cliente_nome', '').strip()
        contrato = request.form.get('contrato', '').strip()

        if not cliente_nome:
            return redirect('/matriculas?erro=cliente_obrigatorio')

        # Converter valores vazios para None
        data = data if data else None
        valor_matricula = float(valor_matricula) if valor_matricula else None
        valor_parcela = float(valor_parcela) if valor_parcela else None
        qtd_parcelas = int(qtd_parcelas) if qtd_parcelas else None
        id_vendedores = id_vendedores if id_vendedores else None
        id_unidades = id_unidades if id_unidades else None

        with get_cursor() as (_, cursor):
            if id_matricula:
                # Editar
                cursor.execute("""
                    UPDATE matriculas SET
                        data=%s, valor_matricula=%s, valor_parcela=%s,
                        qtd_parcelas=%s, id_vendedores=%s, id_unidades=%s,
                        cliente_nome=%s, contrato=%s
                    WHERE id=%s
                """, (data, valor_matricula, valor_parcela, qtd_parcelas,
                      id_vendedores, id_unidades, cliente_nome, contrato, id_matricula))
            else:
                # Criar
                cursor.execute("""
                    INSERT INTO matriculas
                    (data, valor_matricula, valor_parcela, qtd_parcelas,
                     id_vendedores, id_unidades, cliente_nome, contrato)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (data, valor_matricula, valor_parcela, qtd_parcelas,
                      id_vendedores, id_unidades, cliente_nome, contrato))

        return redirect('/matriculas?ok=salvo')

    except Exception as e:
        print(f"[ERRO] Salvar matrícula: {e}")
        return redirect('/matriculas?erro=salvar')


@app.route('/matriculas/deletar/<int:id>', methods=['POST'])
@login_required
def deletar_matricula(id):
    """Deletar matrícula"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("DELETE FROM matriculas WHERE id=%s", (id,))
        return redirect('/matriculas?ok=deletado')
    except Exception as e:
        print(f"[ERRO] Deletar matrícula: {e}")
        return redirect('/matriculas?erro=deletar')


# 💼 VENDEDORES
@app.route('/vendedores')
@login_required
def vendedores():
    """Lista todos os vendedores"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("""
                SELECT v.*, u.nome as unidade_nome, u.sigla
                FROM vendedores v
                LEFT JOIN unidades u ON v.id_unidades = u.id
                ORDER BY v.nome
            """)
            vendedores_list = cursor.fetchall()

            # Buscar unidades para o dropdown
            cursor.execute("SELECT id, nome, sigla FROM unidades ORDER BY nome")
            unidades_list = cursor.fetchall()

        return render_template('vendedores.html', vendedores=vendedores_list, unidades_list=unidades_list)
    except Exception as e:
        print(f"[ERRO] Listar vendedores: {e}")
        return render_template('vendedores.html', vendedores=[], erro="Erro ao carregar vendedores")


@app.route('/vendedores/salvar', methods=['POST'])
@login_required
def salvar_vendedor():
    """Salvar/editar vendedor"""
    try:
        id_vendedor = request.form.get('id', '').strip()
        nome = request.form.get('nome', '').strip()
        id_unidades = request.form.get('id_unidades', '').strip()

        if not nome:
            return redirect('/vendedores?erro=campos_obrigatorios')

        # Tratar id_unidades vazio como NULL
        id_unidades = id_unidades if id_unidades else None

        with get_cursor() as (_, cursor):
            if id_vendedor:
                # Editar
                cursor.execute("""
                    UPDATE vendedores SET
                        nome=%s, id_unidades=%s
                    WHERE id=%s
                """, (nome, id_unidades, id_vendedor))
            else:
                # Criar
                cursor.execute("""
                    INSERT INTO vendedores
                    (nome, id_unidades)
                    VALUES (%s, %s)
                """, (nome, id_unidades))

        return redirect('/vendedores?ok=salvo')

    except Exception as e:
        print(f"[ERRO] Salvar vendedor: {e}")
        return redirect('/vendedores?erro=salvar')


@app.route('/vendedores/deletar/<int:id>', methods=['POST'])
@login_required
def deletar_vendedor(id):
    """Deletar vendedor"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("DELETE FROM vendedores WHERE id=%s", (id,))
        return redirect('/vendedores?ok=deletado')
    except Exception as e:
        print(f"[ERRO] Deletar vendedor: {e}")
        return redirect('/vendedores?erro=deletar')


# 📞 CONTATOS
@app.route('/contatos')
@login_required
def contatos():
    """Lista todos os contatos"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("SELECT * FROM contatos ORDER BY nome")
            contatos_list = cursor.fetchall()

        return render_template('contatos.html', contatos=contatos_list)
    except Exception as e:
        print(f"[ERRO] Listar contatos: {e}")
        return render_template('contatos.html', contatos=[], erro="Erro ao carregar contatos")


@app.route('/contatos/salvar', methods=['POST'])
@login_required
def salvar_contato():
    """Salvar/editar contato"""
    try:
        id_contato = request.form.get('id', '').strip()
        nome = request.form.get('nome', '').strip()
        telefone = request.form.get('telefone', '').strip()
        email = request.form.get('email', '').strip()
        unidades_acesso = request.form.get('unidades_acesso', '').strip()
        observacao = request.form.get('observacao', '').strip()

        if not nome or not telefone:
            return redirect('/contatos?erro=campos_obrigatorios')

        with get_cursor() as (_, cursor):
            if id_contato:
                # Editar
                cursor.execute("""
                    UPDATE contatos SET
                        nome=%s, telefone=%s, email=%s,
                        unidades_acesso=%s, observacao=%s
                    WHERE id=%s
                """, (nome, telefone, email, unidades_acesso, observacao, id_contato))
            else:
                # Criar
                cursor.execute("""
                    INSERT INTO contatos
                    (nome, telefone, email, unidades_acesso, observacao)
                    VALUES (%s, %s, %s, %s, %s)
                """, (nome, telefone, email, unidades_acesso, observacao))

        return redirect('/contatos?ok=salvo')

    except Exception as e:
        print(f"[ERRO] Salvar contato: {e}")
        if 'Duplicate entry' in str(e):
            return redirect('/contatos?erro=telefone_duplicado')
        return redirect('/contatos?erro=salvar')


@app.route('/contatos/deletar/<int:id>', methods=['POST'])
@login_required
def deletar_contato(id):
    """Deletar contato"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("DELETE FROM contatos WHERE id=%s", (id,))
        return redirect('/contatos?ok=deletado')
    except Exception as e:
        print(f"[ERRO] Deletar contato: {e}")
        return redirect('/contatos?erro=deletar')


@app.route('/contatos/enviar-mensagem', methods=['POST'])
@login_required
def enviar_mensagem_contato():
    """Enviar mensagem WhatsApp para um contato"""
    try:
        id_contato = request.form.get('id_contato', '').strip()
        mensagem = request.form.get('mensagem', '').strip()

        if not id_contato or not mensagem:
            return redirect('/contatos?erro=campos_obrigatorios')

        with get_cursor() as (_, cursor):
            # Buscar contato
            cursor.execute("SELECT id, nome, telefone FROM contatos WHERE id=%s", (id_contato,))
            contato = cursor.fetchone()

            if not contato:
                return redirect('/contatos?erro=contato_nao_encontrado')

            # Aqui você integraria com Twilio ou outra API de WhatsApp
            # Por enquanto, vamos registrar na tabela de mensagens
            cursor.execute("""
                INSERT INTO mensagens_whatsapp
                (numero_remetente, nome_remetente, mensagem, tipo_mensagem, id_usuario_resposta)
                VALUES (%s, %s, %s, %s, %s)
            """, (contato['telefone'], contato['nome'], mensagem, 'contato_saida', session.get('usuario_id')))

        return redirect('/contatos?ok=mensagem_enviada')

    except Exception as e:
        print(f"[ERRO] Enviar mensagem contato: {e}")
        return redirect('/contatos?erro=enviar_mensagem')


# 📊 RANKING
@app.route('/api/vendedores-unidade/<int:id_unidade>')
@login_required
def api_vendedores_unidade(id_unidade):
    """Retorna vendedores de uma unidade em JSON"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("""
                SELECT id, nome FROM vendedores
                WHERE id_unidades = %s
                ORDER BY nome
            """, (id_unidade,))
            vendedores = cursor.fetchall()
        return jsonify(vendedores)
    except Exception as e:
        print(f"[ERRO] Buscar vendedores: {e}")
        return jsonify([]), 500


@app.route('/ranking')
@login_required
def ranking():
    """Lista todos os registros de ranking"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("""
                SELECT r.*, u.nome as unidade_nome, u.sigla, v.nome as vendedor_nome
                FROM ranking r
                LEFT JOIN unidades u ON r.id_unidades = u.id
                LEFT JOIN vendedores v ON r.id_vendedores = v.id
                ORDER BY r.data DESC, r.id_unidades
            """)
            ranking_list = cursor.fetchall()

            # Buscar unidades para o dropdown
            cursor.execute("SELECT id, nome, sigla FROM unidades ORDER BY nome")
            unidades_list = cursor.fetchall()

        return render_template('ranking.html', ranking=ranking_list, unidades_list=unidades_list)
    except Exception as e:
        print(f"[ERRO] Listar ranking: {e}")
        return render_template('ranking.html', ranking=[], erro="Erro ao carregar ranking")


@app.route('/ranking/salvar', methods=['POST'])
@login_required
def salvar_ranking():
    """Salvar/editar registros de ranking (um por vendedor)"""
    try:
        id_unidades = request.form.get('id_unidades', '').strip()
        data = request.form.get('data', '').strip()

        # Validar campos obrigatórios
        if not id_unidades or not data:
            return redirect('/ranking?erro=campos_obrigatorios')

        try:
            id_unidades = int(id_unidades)
        except ValueError:
            return redirect('/ranking?erro=valores_invalidos')

        # Buscar arrays de vendedores, visitas e matrículas
        id_vendedores = request.form.getlist('id_vendedores[]')
        visitas_list = request.form.getlist('visitas[]')
        matriculas_list = request.form.getlist('matriculas[]')

        if not id_vendedores:
            return redirect('/ranking?erro=nenhum_vendedor')

        with get_cursor() as (_, cursor):
            # Inserir um registro para cada vendedor
            for i, id_vendedor in enumerate(id_vendedores):
                try:
                    id_vendedor = int(id_vendedor)
                    visitas = int(visitas_list[i]) if i < len(visitas_list) and visitas_list[i] else None
                    matriculas = int(matriculas_list[i]) if i < len(matriculas_list) and matriculas_list[i] else None

                    cursor.execute("""
                        INSERT INTO ranking
                        (id_unidades, id_vendedores, data, visitas, matriculas)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (id_unidades, id_vendedor, data, visitas, matriculas))
                except (ValueError, IndexError) as e:
                    print(f"[AVISO] Erro ao processar vendedor {id_vendedor}: {e}")
                    continue

        return redirect('/ranking?ok=salvo')

    except Exception as e:
        print(f"[ERRO] Salvar ranking: {e}")
        return redirect('/ranking?erro=salvar')


@app.route('/ranking/deletar/<int:id>', methods=['POST'])
@login_required
def deletar_ranking(id):
    """Deletar registro de ranking"""
    try:
        with get_cursor() as (_, cursor):
            cursor.execute("DELETE FROM ranking WHERE id=%s", (id,))
        return redirect('/ranking?ok=deletado')
    except Exception as e:
        print(f"[ERRO] Deletar ranking: {e}")
        return redirect('/ranking?erro=deletar')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)