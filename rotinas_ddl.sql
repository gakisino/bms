-- ============================================================
-- DDL — Tabela de rotinas do sistema e controle de acesso
-- Execute no banco `bms`
-- ============================================================

-- Tabela de rotinas disponíveis no sistema
CREATE TABLE IF NOT EXISTS rotinas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL UNIQUE,
    descricao TEXT,
    url VARCHAR(255),
    ativo TINYINT(1) DEFAULT 1 COMMENT '1 = ativa',
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Rotinas/funcionalidades do sistema';

-- Inserir rotinas padrão (atualize conforme suas rotinas reais)
INSERT IGNORE INTO rotinas (nome, descricao, url, ativo) VALUES
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

-- Adicionar índices para melhor performance
ALTER TABLE rotinas_acesso ADD CONSTRAINT fk_ra_perfil
    FOREIGN KEY (id_perfil) REFERENCES perfil(id) ON DELETE CASCADE;
ALTER TABLE rotinas_acesso ADD CONSTRAINT fk_ra_rotina
    FOREIGN KEY (id_rotinas) REFERENCES rotinas(id) ON DELETE CASCADE;
