import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/*
 * Sistema simples de login
 * - Persiste usuários em `users.txt` no formato: username:sha256(password):ROLE
 * - Cria um administrador padrão se o arquivo não existir (admin/admin123)
 * - Separa menus por papel: ADMIN e USER
 */
public class Login {

	private static final String USERS_FILE = "users.txt";
    // Arquivo onde os usuários são salvos (no mesmo diretório do programa)
	private static final String DEFAULT_ADMIN = "admin"; // nome de admin padrão
    // Conta administrativa padrão criada na primeira execução
	private static final String DEFAULT_ADMIN_PASS = "admin123"; // senha de exemplo (mudar após o primeiro uso)

	enum Role { ADMIN, USER }

    // Papéis possíveis no sistema: Administrador e Usuário comum
	static class User {
		String username;
		String passwordHash;
		Role role;

		User (String username, String passwordHash, Role role) {
			this.username = username;
			this.passwordHash = passwordHash;
			this.role = role;
		}

	/*
	 * Representação simples de um usuário.
	 * - username: login do usuário
	 * - passwordHash: hash SHA-256 da senha (não armazenamos texto puro)
	 * - role: papel (ADMIN ou USER)
	 *
	 * Métodos utilitários:
	 * - toLine(): converte para a linha que será escrita em users.txt
	 * - fromLine(): reconstrói um User a partir de uma linha do arquivo
	 */
		String toLine () {
			return username + ":" + passwordHash + ":" + role.name ();
		}

		static User fromLine (String line) {
			String[] parts = line.split(":");
			if (parts.length != 3) return null;
			String u = parts[0];
			String h = parts[1];
			Role r;
			try {
				r = Role.valueOf (parts[2]);
			} catch (IllegalArgumentException e) {
				return null;
			}
			return new User (u, h, r);
		}
	}

    // Mapa em memória com os usuários carregados do arquivo (chave = username)
	private final Map<String, User> users = new HashMap<> ();

	public static void main (String[] args) {
		Login app = new Login ();
		app.run ();
	}

	void run () {
		loadUsers ();

		try (Scanner sc = new Scanner (System.in)) {
			mainLoop: while (true) {
				System.out.println ("==== Sistema de Login ====\n");
				System.out.println ("1) Entrar");
				System.out.println ("2) Registrar novo usuário");
				System.out.println ("3) Sair");
				System.out.print ("Escolha uma opção: \n");

                /*
                 * Loop principal da aplicação.
                 * - Carrega usuários do arquivo
                 * - Mostra um menu simples para entrar, registrar ou sair
                 */
				String opt = sc.nextLine().trim();
				switch (opt) {
					case "1" -> handleLogin (sc);
					case "2" -> handleRegister (sc);
					case "3" -> {
                                            System.out.println ("Saindo...");
                                            break mainLoop;
                                }
					default -> System.out.println ("Opção inválida.");
				}
				System.out.println ();
			}
		}
	}

	private void handleLogin (Scanner sc) {
		System.out.print ("Usuário: ");
		String user = sc.nextLine ().trim ();
		System.out.print ("Senha: ");
		String pass = sc.nextLine ();

		User u = users.get (user);
		if (u == null) {
			System.out.println ("Usuário não encontrado.");
			return;
		}

        // Verifica se o usuário existe em memória
		String hash = hash (pass);
		if (!u.passwordHash.equals (hash)) {
			System.out.println ("Senha incorreta.");
			return;
		}

        // Redireciona para o menu conforme o papel do usuário
		System.out.println ("Login efetuado: " + u.username + " (" + u.role + ")");
		if (u.role == Role.ADMIN) {
			adminMenu (sc, u);
		} else {
			userMenu (sc, u);
		}
	}

    // Fluxo de registro de novo usuário (sempre criado com papel USER)
	private void handleRegister (Scanner sc) {
		System.out.print ("Novo usuário (login): ");
		String user = sc.nextLine ().trim ();
		if (user.isEmpty ()) {
			System.out.println ("Nome de usuário vazio.");
			return;
		}
		if (users.containsKey (user)) {
			System.out.println ("Usuário já existe.");
			return;
		}
		System.out.print ("Senha: ");
		String pass = sc.nextLine ();
		System.out.print ("Confirme a senha: ");
		String pass2 = sc.nextLine ();
		if (!pass.equals (pass2)) {
			System.out.println ("Senhas não conferem.");
			return;
		}

        // Armazena somente o hash da senha
		String hash = hash (pass);
		User nu = new User (user, hash, Role.USER);
		users.put (user, nu);
		saveUsers ();
		System.out.println ("Usuário registrado com sucesso. Faça o login.");
	}

    /*
     * Menu disponível apenas para administradores.
     * Possui opções para listar, remover, promover/criar admin e alterar a senha do próprio admin.
     */
	private void adminMenu (Scanner sc, User logged) {
		while (true) {
			System.out.println ("\n--- Menu Admin ---");
			System.out.println ("1) Listar usuários");
			System.out.println ("2) Remover usuário");
			System.out.println ("3) Criar/Promover administrador");
			System.out.println ("4) Alterar senha (admin)");
			System.out.println ("5) Logout");
			System.out.print ("Opção: ");
			String o = sc.nextLine ().trim ();
			switch (o) {
				case "1" -> listUsers ();
				case "2" -> {
                    // Remoção de usuário (protege o admin padrão)
                    System.out.print ("Usuário a remover: ");
                    String toRem = sc.nextLine ().trim ();
                    if (toRem.equals (DEFAULT_ADMIN)) {
                        System.out.println ("Não é permitido remover o admin padrão.");
                        break;
                    }
                    if (users.remove (toRem) != null) {
                        saveUsers ();
                        System.out.println ("Removido: " + toRem);
                    } else {
                        System.out.println ("Usuário não encontrado.");
                    }
                        }
				case "3" -> {
                    // Promove um usuário existente para admin ou cria um novo admin
                                    System.out.print ("Usuário a criar/promover como admin: ");
                                    String name = sc.nextLine ().trim ();
                                    if (name.isEmpty ()) {
                                        System.out.println ("Nome inválido.");
                                        break;
                                    }
                                    if (users.containsKey (name)) {
                                        User ex = users.get (name);
                                        if (ex.role == Role.ADMIN) {
                                            System.out.println ("Já é administrador: " + name);
                                        } else {
                                            ex.role = Role.ADMIN;
                                            saveUsers();
                                            System.out.println ("Promovido para admin: " + name);
                                        }
                                    } else {
                                        System.out.print ("Senha para novo admin: ");
                                        String p = sc.nextLine ();
                                        System.out.print ("Confirme a senha: ");
                                        String p2 = sc.nextLine ();
                                        if (!p.equals (p2)) {
                                            System.out.println ("Senhas não conferem.");
                                            break;
                                        }
                                        User na = new User (name, hash (p), Role.ADMIN);
                                        users.put (name, na);
                                        saveUsers ();
                                        System.out.println ("Administrador criado: " + name);
                                    }
                        }
				case "4" -> {
                    // Alterar a senha do admin logado
                                    System.out.print ("Nova senha: ");
                                    String np = sc.nextLine ();
                                    users.get (logged.username).passwordHash = hash (np);
                                    saveUsers ();
                                    System.out.println ("Senha alterada.");
                        }
				case "5" -> {
                                    System.out.println ("Logout.");
                                    return;
                        }
				default -> System.out.println ("Opção inválida.");
			}
		}
	}

	private void userMenu (Scanner sc, User logged) {
		while (true) {
			System.out.println ("\n--- Menu Usuário ---");
			System.out.println ("1) Ver perfil");
			System.out.println ("2) Alterar senha");
			System.out.println ("3) Logout");
			System.out.print ("Opção: ");
			String o = sc.nextLine ().trim ();
			switch (o) {
				case "1" -> {
                                    System.out.println ("Usuário: " + logged.username);
                                    System.out.println ("Papel: " + logged.role);
                        }
				case "2" -> {
                                    System.out.print ("Senha atual: ");
                                    String cur = sc.nextLine ();
                                    if (!logged.passwordHash.equals (hash (cur))) {
                                        System.out.println ("Senha atual incorreta.");
                                        break;
                                    }
                                    System.out.print ("Nova senha: ");
                                    String np = sc.nextLine ();
                                    users.get (logged.username).passwordHash = hash (np);
                                    saveUsers ();
                                    System.out.println ("Senha alterada.");
                        }
				case "3" -> {
                                    System.out.println ("Logout.");
                                    return;
                        }
				default -> System.out.println ("Opção inválida.");
			}
		}
	}

	private void listUsers () {
		Collection<User> c = users.values ();
		System.out.println ("Usuários registrados:");
		for (User u : c) {
			System.out.println (" - " + u.username + " (" + u.role + ")");
		}
	}

	private void loadUsers() {
		File f = new File (USERS_FILE);
		if (!f.exists ()) {
			System.out.println ("Arquivo de usuários não encontrado. Criando com admin padrão.");
			String hash = hash (DEFAULT_ADMIN_PASS);
			User admin = new User (DEFAULT_ADMIN, hash, Role.ADMIN);
			users.put (DEFAULT_ADMIN, admin);
			saveUsers ();
			return;
		}

		try (BufferedReader br = new BufferedReader (new FileReader (f))) {
			String line;
			while ((line = br.readLine ()) != null) {
				User u = User.fromLine (line.trim ());
				if (u != null) users.put (u.username, u);
			}
		} catch (IOException e) {
			System.out.println ("Erro ao ler usuários: " + e.getMessage ());
		}
	}

	private void saveUsers() {
		File f = new File (USERS_FILE);
		try (BufferedWriter bw = new BufferedWriter (new FileWriter (f))) {
			for (User u : users.values ()) {
				bw.write (u.toLine ());
				bw.newLine ();
			}
		} catch (IOException e) {
			System.out.println ("Erro ao salvar usuários: " + e.getMessage ());
		}
	}

	private static String hash (String input) {
		if (input == null) input = "";
		try {
			MessageDigest md = MessageDigest.getInstance ("SHA-256");
			byte[] b = md.digest (input.getBytes (StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder ();
			for (byte x : b) sb.append (String.format ("%02x", x));
			return sb.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException (e);
		}
	}
}