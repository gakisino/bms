function toggleSidebar() {
    const sidebar = document.getElementById("sidebar");
    const btn = document.querySelector(".toggle-btn");

    sidebar.classList.toggle("collapsed");

    if (sidebar.classList.contains("collapsed")) {
        btn.innerHTML = "⮞";
    } else {
        btn.innerHTML = "⮜";
    }
}

function abrirModal() {
    document.getElementById("modal").style.display = "flex";
}

function fecharModal() {
    document.getElementById("modal").style.display = "none";
}

// Captura o modal e o botão
const modal = document.getElementById("modalUsuario");
const btnNovo = document.querySelector(".btn"); // Aquele botão que você já tinha

// Abrir ao clicar no + Novo Usuário
btnNovo.onclick = function() {
    modal.style.display = "block";
}

// Fechar modal
function fecharModal() {
    modal.style.display = "none";
}

// Fechar se clicar fora da caixa branca
window.onclick = function(event) {
    if (event.target == modal) {
        fecharModal();
    }
}