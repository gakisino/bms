# 🔐 Sistema de Controle de Acesso às Rotinas

## 📋 Passos para Configuração

### 1. **Criar a Tabela `rotinas` no Banco de Dados**

Execute este SQL no seu banco `bms`:

```sql
-- Tabela de rotinas disponíveis no sistema
CREATE TABLE IF NOT EXISTS rotinas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL UNIQUE,
    descricao TEXT,
    url VARCHAR(255),
    ativo TINYINT(1) DEFAULT 1 COMMENT '1 = ativa',
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Rotinas/funcionalidades do sistema';

-- Inserir as rotinas do seu sistema
INSERT INTO rotinas (nome, descricao, url, ativo) VALUES
('Dashboard', 'Visualizar dashboard do sistema', '/dashboard', 1),
('Agenda', 'Gerenciar agendamentos', '/agenda', 1),
('Agendamento', 'Novo agendamento de atendimento', '/agendamento', 1),
('Prêmios', 'Gerenciar prêmios por meta', '/premios', 1),
('Tabela de Prêmios', 'Manutenção da tabela de prêmios', '/premios_tabela', 1),
('Usuários', 'Gerenciar usuários do sistema', '/usuarios', 1),
('Perfis', 'Gerenciar perfis de usuário', '/perfil', 1),
('Operadores', 'Gerenciar operadores/colaboradores', '/operadores', 1),
('Permissões Prêmios', 'Controle de acesso à rotina de prêmios', '/premios/permissoes', 1),
('Acesso às Rotinas', 'Gerenciar acesso às rotinas por perfil', '/rotinas/permissoes', 1);

-- Adicionar constraint na tabela rotinas_acesso (se ainda não tiver)
ALTER TABLE rotinas_acesso ADD CONSTRAINT fk_ra_perfil
    FOREIGN KEY (id_perfil) REFERENCES perfil(id) ON DELETE CASCADE;

ALTER TABLE rotinas_acesso ADD CONSTRAINT fk_ra_rotina
    FOREIGN KEY (id_rotinas) REFERENCES rotinas(id) ON DELETE CASCADE;
```

### 2. **Acessar a Página de Configuração**

Vá em: **Configurações → Acesso às Rotinas**

### 3. **Configurar Permissões**

- Selecione um **Perfil**
- Para cada rotina, escolha um nível de acesso:
  - 🟢 **Verde**: Acesso Total (CRUD - Criar, Ler, Editar, Deletar)
  - 🟡 **Amarelo**: Somente Leitura
  - 🔴 **Vermelho**: Sem Acesso (deleta da tabela)

### 4. **Como Funciona**

#### ✅ Tabela `rotinas_acesso`

Estrutura:
```sql
id              INT PRIMARY KEY
id_perfil       INT (FK → perfil.id)
id_rotinas      INT (FK → rotinas.id)
acesso          VARCHAR(1) → 'A' (Alteração) ou 'L' (Leitura)
```

#### 🔄 Lógica de Salvamento

```python
if acesso == 'V':  # Vermelho (sem acesso)
    DELETE FROM rotinas_acesso WHERE id_perfil = X AND id_rotinas = Y

elif acesso == 'G':  # Verde (acesso total)
    INSERT/UPDATE rotinas_acesso SET acesso = 'A'

elif acesso == 'A':  # Amarelo (somente leitura)
    INSERT/UPDATE rotinas_acesso SET acesso = 'L'
```

### 5. **Verificação de Acesso no Login**

Quando um usuário faz login:
1. Sistema carrega lista de rotinas que ele pode acessar
2. Menu é filtrado (mostra apenas rotinas acessíveis)
3. Se tentar acessar rota sem permissão, é redirecionado

### 6. **Proteger uma Rota Específica**

Para forçar verificação de acesso em uma rota:

```python
@app.route('/recurso-protegido')
@login_required
def recurso_protegido():
    # Verificar acesso manualmente
    acesso = verificar_acesso_rotina(session['usuario_id'], id_rotina=5)
    
    if not acesso:
        return redirect('/dashboard')
    
    if acesso == 'L':  # Leitura
        # Mostrar sem botões de edição/delete
        pass
    elif acesso == 'A':  # Alteração
        # Mostrar com CRUD completo
        pass
    
    return render_template('sua_pagina.html')
```

## 🛠 Funções Disponíveis

### `verificar_acesso_rotina(id_usuario, id_rotina)`
Retorna: `'A'` (Alteração), `'L'` (Leitura), ou `None` (Sem acesso)

### `obter_rotinas_acesso_usuario(id_usuario)`
Retorna: Lista de IDs de rotinas que o usuário pode acessar

### `tem_acesso_rotina(id_rotina)` (nos templates)
Retorna: `True/False` - use nos templates Jinja2

## 📊 Exemplo de Fluxo

```
1. Usuário faz login com email: operador@example.com
   ↓
2. Sistema busca perfil: "Operador"
   ↓
3. Sistema busca na tabela rotinas_acesso:
   - Perfil "Operador" + Rotina "Agenda" = 'A' (Alteração)
   - Perfil "Operador" + Rotina "Prêmios" = 'L' (Leitura)
   - Perfil "Operador" + Rotina "Usuários" = sem registro (Sem acesso)
   ↓
4. Menu mostra: Dashboard, Agenda, Agendamento, Prêmios
   (não mostra: Usuários, Perfis, Operadores, etc)
   ↓
5. Se tentar acessar /usuarios → Redirecionado para /dashboard
```

## 🐛 Troubleshooting

### "Volta para login ao tentar acessar /rotinas/permissoes"

**Causa**: Erro na função de verificação de acesso

**Solução**:
1. Verifique se a tabela `rotinas_acesso` existe:
```sql
DESCRIBE rotinas_acesso;
```

2. Verifique console do Flask para erros:
```bash
# No terminal onde Flask está rodando, veja os logs
```

3. Certifique-se que o usuário logado tem um `id_perfil` válido:
```sql
SELECT id, nome, id_perfil FROM usuarios;
```

---

**✅ Sistema pronto para usar!** 🎉
