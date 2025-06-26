import time
import os
import customtkinter as ctk
from tkinter import messagebox
from PIL import Image


class Usuario:
    usuarios_cadastrados = []

    def __init__(self, nome, email, senha, admin=False):
        self.nome = nome
        self.email = email
        self.senha = senha
        self.logado = False
        self.admin = admin
        if not any(u.email == email for u in Usuario.usuarios_cadastrados):
            Usuario.usuarios_cadastrados.append(self)
        else:
            raise ValueError(f"Email {email} já cadastrado!")

    def login(self, nome_input, senha_input):
        if nome_input == self.nome and senha_input == self.senha:
            self.logado = True
            return True
        return False

    def logout(self):
        self.logado = False


class Admin(Usuario):
    def __init__(self, nome, email, senha):
        super().__init__(nome, email, senha, admin=True)


class UserSystemApp:
    def __init__(self):
        # Configuração da janela principal
        self.root = ctk.CTk()
        self.root.title("Sistema de Usuários")
        self.root.geometry("800x600")

        # Configuração do tema
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Variáveis de estado
        self.usuario_logado = None

        # Criar admin padrão
        try:
            Admin(nome="Yan", email="yanguilherme2927@gmail.com", senha="Yan2906")
        except ValueError:
            pass

        # Carregar imagens
        self.load_images()

        # Iniciar com a tela de login
        self.show_login_screen()

        self.root.mainloop()

    def load_images(self):
        # Aqui você pode adicionar imagens se quiser
        pass

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_frame()

        # Frame principal
        frame = ctk.CTkFrame(self.root, fg_color="transparent")
        frame.pack(expand=True, fill="both", padx=50, pady=50)

        # Título
        title_label = ctk.CTkLabel(frame, text="SISTEMA DE USUÁRIOS",
                                   font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(0, 30))

        # Campos de entrada
        login_frame = ctk.CTkFrame(frame, fg_color="transparent")
        login_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(login_frame, text="Nome:").pack(anchor="w")
        self.nome_entry = ctk.CTkEntry(login_frame)
        self.nome_entry.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(login_frame, text="Senha:").pack(anchor="w")
        self.senha_entry = ctk.CTkEntry(login_frame, show="*")
        self.senha_entry.pack(fill="x", pady=(0, 20))

        # Botões
        button_frame = ctk.CTkFrame(frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)

        login_button = ctk.CTkButton(button_frame, text="Login", command=self.do_login)
        login_button.pack(side="left", fill="x", expand=True, padx=5)

        register_button = ctk.CTkButton(button_frame, text="Cadastrar", command=self.show_register_screen)
        register_button.pack(side="left", fill="x", expand=True, padx=5)

        # Configurar entrada com Enter
        self.senha_entry.bind("<Return>", lambda e: self.do_login())

    def show_register_screen(self):
        self.clear_frame()

        # Frame principal
        frame = ctk.CTkFrame(self.root, fg_color="transparent")
        frame.pack(expand=True, fill="both", padx=50, pady=50)

        # Título
        title_label = ctk.CTkLabel(frame, text="CADASTRO DE USUÁRIO",
                                   font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(0, 30))

        # Campos de entrada
        register_frame = ctk.CTkFrame(frame, fg_color="transparent")
        register_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(register_frame, text="Nome:").pack(anchor="w")
        self.reg_nome_entry = ctk.CTkEntry(register_frame)
        self.reg_nome_entry.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(register_frame, text="Email:").pack(anchor="w")
        self.reg_email_entry = ctk.CTkEntry(register_frame)
        self.reg_email_entry.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(register_frame, text="Senha:").pack(anchor="w")
        self.reg_senha_entry = ctk.CTkEntry(register_frame, show="*")
        self.reg_senha_entry.pack(fill="x", pady=(0, 20))

        self.admin_var = ctk.BooleanVar()
        admin_check = ctk.CTkCheckBox(register_frame, text="Administrador", variable=self.admin_var)
        admin_check.pack(pady=(0, 20))

        # Botões
        button_frame = ctk.CTkFrame(frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)

        register_button = ctk.CTkButton(button_frame, text="Cadastrar", command=self.do_register)
        register_button.pack(side="left", fill="x", expand=True, padx=5)

        back_button = ctk.CTkButton(button_frame, text="Voltar", command=self.show_login_screen)
        back_button.pack(side="left", fill="x", expand=True, padx=5)

        # Configurar entrada com Enter
        self.reg_senha_entry.bind("<Return>", lambda e: self.do_register())

    def show_main_menu(self):
        self.clear_frame()

        # Frame principal
        frame = ctk.CTkFrame(self.root, fg_color="transparent")
        frame.pack(expand=True, fill="both", padx=50, pady=50)

        # Título e informações do usuário
        tipo = "ADMIN" if self.usuario_logado.admin else "USUÁRIO"
        color = "#FF5555" if self.usuario_logado.admin else "#55FF55"

        title_label = ctk.CTkLabel(frame, text="MENU PRINCIPAL",
                                   font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(0, 10))

        user_label = ctk.CTkLabel(frame,
                                  text=f"Logado como: {self.usuario_logado.nome} | Tipo: {tipo}",
                                  text_color=color)
        user_label.pack(pady=(0, 30))

        # Botões do menu
        menu_frame = ctk.CTkFrame(frame, fg_color="transparent")
        menu_frame.pack(fill="x", pady=10)

        buttons = [
            ("Cadastrar novo usuário", self.show_register_screen),
            ("Listar usuários", self.show_user_list),
            ("Fazer logout", self.do_logout)
        ]

        for text, command in buttons:
            button = ctk.CTkButton(menu_frame, text=text, command=command)
            button.pack(fill="x", pady=5)

        # Botão de sair
        exit_button = ctk.CTkButton(frame, text="Sair", command=self.root.quit, fg_color="transparent",
                                    border_width=1, text_color=("gray10", "#DCE4EE"))
        exit_button.pack(fill="x", pady=(20, 0))

    def show_user_list(self):
        if not self.usuario_logado or not self.usuario_logado.logado:
            messagebox.showwarning("Aviso", "Faça login primeiro!")
            return

        if not self.usuario_logado.admin:
            messagebox.showerror("Erro", "Acesso restrito a administradores!")
            return

        self.clear_frame()

        # Frame principal
        frame = ctk.CTkFrame(self.root, fg_color="transparent")
        frame.pack(expand=True, fill="both", padx=50, pady=50)

        # Título
        title_label = ctk.CTkLabel(frame, text="USUÁRIOS CADASTRADOS",
                                   font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(0, 30))

        # Lista de usuários
        list_frame = ctk.CTkScrollableFrame(frame)
        list_frame.pack(expand=True, fill="both")

        for user in Usuario.usuarios_cadastrados:
            tipo = "ADMIN" if user.admin else "USUÁRIO"
            color = "#FF5555" if user.admin else "#55FF55"

            user_frame = ctk.CTkFrame(list_frame, fg_color="transparent")
            user_frame.pack(fill="x", pady=5)

            ctk.CTkLabel(user_frame,
                         text=f"{user.nome} | {user.email} | {tipo}",
                         text_color=color).pack(side="left")

            # Botão para remover (apenas admin pode remover)
            if self.usuario_logado.admin and user != self.usuario_logado:
                remove_btn = ctk.CTkButton(user_frame, text="Remover", width=30,
                                           command=lambda u=user: self.remove_user(u))
                remove_btn.pack(side="right", padx=5)

        # Botão de voltar
        back_button = ctk.CTkButton(frame, text="Voltar", command=self.show_main_menu)
        back_button.pack(pady=(20, 0))

    def do_login(self):
        nome = self.nome_entry.get()
        senha = self.senha_entry.get()

        if not nome or not senha:
            messagebox.showwarning("Aviso", "Preencha todos os campos!")
            return

        for usuario in Usuario.usuarios_cadastrados:
            if usuario.login(nome, senha):
                self.usuario_logado = usuario
                messagebox.showinfo("Sucesso",
                                    f"Bem-vindo {'ADMIN ' if usuario.admin else ''}{usuario.nome}!")
                self.show_main_menu()
                return

        messagebox.showerror("Erro", "Credenciais inválidas!")

    def do_register(self):
        nome = self.reg_nome_entry.get()
        email = self.reg_email_entry.get()
        senha = self.reg_senha_entry.get()
        admin = self.admin_var.get()

        if not nome or not email or not senha:
            messagebox.showwarning("Aviso", "Preencha todos os campos!")
            return

        try:
            if admin:
                Admin(nome=nome, email=email, senha=senha)
            else:
                Usuario(nome=nome, email=email, senha=senha)

            messagebox.showinfo("Sucesso", f"{'Admin' if admin else 'Usuário'} criado com sucesso!")

            if self.usuario_logado and self.usuario_logado.logado:
                self.show_main_menu()
            else:
                self.show_login_screen()

        except ValueError as e:
            messagebox.showerror("Erro", str(e))

    def do_logout(self):
        if self.usuario_logado:
            self.usuario_logado.logout()
            messagebox.showinfo("Info", f"Até logo, {self.usuario_logado.nome}!")
            self.usuario_logado = None
            self.show_login_screen()
        else:
            messagebox.showwarning("Aviso", "Nenhum usuário logado no momento!")

    def remove_user(self, user):
        if not self.usuario_logado or not self.usuario_logado.admin:
            return

        if messagebox.askyesno("Confirmar", f"Remover usuário {user.nome}?"):
            Usuario.usuarios_cadastrados.remove(user)
            self.show_user_list()
            messagebox.showinfo("Sucesso", "Usuário removido com sucesso!")


# Iniciar aplicação
if __name__ == "__main__":
    app = UserSystemApp()