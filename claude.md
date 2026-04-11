# Projeto
Aplicação web em Python com Flask, frontend em HTML/CSS/JS puro e banco de dados MySQL/PostgreSQL.
Intranet para gerenciamento de rotinas como agendamento de visitas, pagamento de premios por metas atingidas, envio de mensagem pelo whatsapp a todos os colaboradores envolvidos.

# Sobre o negócio
Aplicação para escola de cursos de informática voltada para jovens. Com 3 unidades operando : Santana SAN, Santo Amaro STO e Sao Jose dos Campos SJC.

Público-alvo: Colaboradores internos para automatização de tarefas e afazeres diários com a intenção de eliminar rotinas manuais principais baseadas em controle por planilhas Excel e afins.

# Terminologia do projeto
- Usuário : Usuários cadastrados a operar no sistema.
- Unidades : Escolas que compõe o grupo BMS , atualmente são 3 Santana SAN, Santo Amaro STO e Sao Jose dos Campos SJC.
- Operadores : Colaboradores da escola que são atores que agendam atendimentos e podem receber premios de meta atingidas e controladas pelo sistema.
- Agendamento : Rotina que visa controlar sistema de agendamento para as unidades do grupo de Escola
- Responsável: pai ou mãe do aluno menor de idade

# Regras de negócio importantes



# Stack
- Backend: Python + Flask
- Frontend: HTML, CSS, JavaScript puro
- Banco de dados: MySQL
- Templates: Jinja2 (Flask)

# Estrutura típica
- app.py ou run.py — ponto de entrada da aplicação
- /templates — arquivos HTML (Jinja2)
- /static — arquivos CSS, JS e imagens
# - /routes — rotas da aplicação
# - /models — modelos do banco de dados

# Comandos úteis
- Para rodar: flask run ou python app.py
- Para instalar dependências: pip install -r requirements.txt

# Padrões do projeto
- Usar português nos comentários e mensagens de erro
- Seguir estrutura de blueprints do Flask quando possível
- Sempre validar dados antes de inserir no banco