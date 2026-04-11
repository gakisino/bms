-- ============================================================
-- DDL — Tabela de permissões de prêmios
-- Execute no banco `bms`
-- As tabelas premios, premios_rateio e a coluna senha_eletronica
-- em usuarios já existem.
-- ============================================================

CREATE TABLE IF NOT EXISTS premios_permissoes (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario      INT NOT NULL,
    pode_incluir    TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = pode incluir prêmios',
    pode_autorizar  TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = pode autorizar/pagar prêmios',
    UNIQUE KEY uk_usuario (id_usuario),
    CONSTRAINT fk_pp_usuario FOREIGN KEY (id_usuario) REFERENCES usuarios(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Controle de acesso à rotina de prêmios';
