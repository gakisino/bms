-- Tabela de Ranking
CREATE TABLE IF NOT EXISTS ranking (
    id INT PRIMARY KEY AUTO_INCREMENT,
    id_unidades INT,
    data DATE,
    visitas INT,
    matriculas INT,
    data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP,
    data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (id_unidades) REFERENCES unidades(id) ON DELETE SET NULL,
    INDEX idx_unidades (id_unidades),
    INDEX idx_data (data)
);
