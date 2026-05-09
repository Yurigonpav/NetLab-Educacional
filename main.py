# main.py
# Ponto de entrada do NetLab Educacional.
# Inicializa a aplicação Qt, aplica o tema visual e abre a janela principal.

import sys
import os

from PyQt6.QtWidgets import QApplication, QStyleFactory
from PyQt6.QtGui import QIcon

from interface.janela_principal import JanelaPrincipal
from utils.caminhos import recurso_path


def iniciar_aplicacao():
    """Configura e inicializa toda a aplicação."""

    # Necessário antes de criar QApplication no Windows com HiDPI
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

    app = QApplication(sys.argv)

    # Forçar estilo Fusion para consistência entre ambientes
    app.setStyle(QStyleFactory.create("Fusion"))

    # Metadados da aplicação
    app.setApplicationName("NetLab Educacional")
    app.setApplicationVersion("5.0")
    app.setOrganizationName("TCC - Técnico em Informática - Yuri Gonçalves Pavão")

    # Definir o ícone da aplicação (janela e barra de tarefas)
    caminho_icone = recurso_path("icone.ico")
    if os.path.exists(caminho_icone):
        app.setWindowIcon(QIcon(caminho_icone))

    # Carregar folha de estilos personalizada (tema escuro) usando recurso_path
    caminho_estilo = recurso_path(os.path.join("recursos", "estilos", "tema_escuro.qss"))

    if os.path.exists(caminho_estilo):
        with open(caminho_estilo, "r", encoding="utf-8") as arquivo:
            app.setStyleSheet(arquivo.read())
        print(f"Estilo carregado de: {caminho_estilo}")
    else:
        print(f"ERRO: Arquivo de estilo não encontrado em {caminho_estilo}")
        print("   Verifique se a pasta 'recursos' foi incluída no build.")

    # Criar e exibir a janela principal
    janela = JanelaPrincipal()
    janela.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    iniciar_aplicacao()
