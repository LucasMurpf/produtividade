import time
from datetime import datetime, date
import hashlib
import base64
import logging
import uuid
from contextlib import contextmanager
import streamlit as st
from sqlalchemy import Boolean, Column, DateTime, Date, Integer, String, Text, ForeignKey, create_engine, text, inspect
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import pandas as pd
import bcrypt

# --- CONFIGURAÇÃO DE LOGGING ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(
    page_title="Lucid Productive", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- DESIGN SYSTEM & TOKENS DE ESTILO ---
GLOBAL_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    html, body, [class*="css"] { 
        font-family: 'Inter', sans-serif !important; 
    }

    .main { 
        background-color: #0b0f19; 
        color: #f1f5f9; 
        background-image: radial-gradient(circle at 10% 20%, rgba(37, 99, 235, 0.04) 0%, transparent 40%);
    }
    
    /* Card de Autenticação Estilo Glassmorphism */
    [data-testid="stForm"] {
        background-color: rgba(17, 24, 39, 0.5) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        backdrop-filter: blur(20px) !important;
        border-radius: 16px !important;
        padding: 2rem !important;
        box-shadow: 0 16px 40px rgba(0, 0, 0, 0.5) !important;
    }

    [data-baseweb="input"] > div {
        background-color: rgba(0, 0, 0, 0.3) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 8px !important;
    }

    .stButton>button { 
        width: 100%; 
        border-radius: 8px; 
        font-weight: 500; 
        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
        color: #ffffff; 
        border: none;
        padding: 0.5rem 1rem;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        opacity: 0.9;
        box-shadow: 0 4px 20px rgba(37, 99, 235, 0.4);
    }
</style>
"""
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

# --- BANCO DE DADOS & PERSISTÊNCIA ---
DATABASE_URL = "sqlite:///produtividade_pro.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        db.rollback()
        logger.error(f"Erro na transacao do banco: {e}")
        raise
    finally:
        db.close()


# --- MODELOS SQLALCHEMY ---
class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    senha_hash = Column(String, nullable=False)
    reset_token = Column(String, nullable=True)
    session_token = Column(String, nullable=True)
    
    tarefas_criadas = relationship("Tarefa", foreign_keys="Tarefa.criador_id", backref="criador", cascade="all, delete-orphan")
    tarefas_atribuidas = relationship("Tarefa", foreign_keys="Tarefa.responsavel_id", backref="responsavel_user", cascade="all, delete-orphan")
    subtarefas_atribuidas = relationship("SubTarefa", foreign_keys="SubTarefa.responsavel_id", backref="responsavel_sub", cascade="all, delete-orphan")
    anotacoes = relationship("Anotacao", backref="usuario", cascade="all, delete-orphan")
    notificacoes = relationship("Notificacao", backref="usuario", cascade="all, delete-orphan")


class Notificacao(Base):
    __tablename__ = "notificacoes"
    id = Column(Integer, primary_key=True, index=True)
    mensagem = Column(String, nullable=False)
    lida = Column(Boolean, default=False)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))


class SubTarefa(Base):
    __tablename__ = "subtarefas"
    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String, nullable=False)
    concluida = Column(Boolean, default=False)
    prazo = Column(Date, nullable=True)
    imagem_base64 = Column(Text, nullable=True)
    tarefa_id = Column(Integer, ForeignKey("tarefas.id"))
    responsavel_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)


class Tarefa(Base):
    __tablename__ = "tarefas"
    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String, nullable=False)
    status_kanban = Column(String, default="A Fazer")
    concluida = Column(Boolean, default=False)
    prioridade = Column(String, default="Média")
    prazo = Column(Date, nullable=True)
    
    criador_id = Column(Integer, ForeignKey("usuarios.id"))
    responsavel_id = Column(Integer, ForeignKey("usuarios.id"))
    
    subtarefas = relationship("SubTarefa", backref="tarefa", cascade="all, delete-orphan")


class Anotacao(Base):
    __tablename__ = "anotacoes"
    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String, nullable=False)
    tags = Column(String, nullable=False)
    conteudo = Column(Text, nullable=True)
    imagem_base64 = Column(Text, nullable=True)
    data_criacao = Column(DateTime, default=datetime.utcnow)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))


Base.metadata.create_all(bind=engine)

# Migração segura de colunas
try:
    inspector = inspect(engine)
    if 'usuarios' in inspector.get_table_names():
        colunas = [col['name'] for col in inspector.get_columns('usuarios')]
        if 'reset_token' not in colunas:
            with engine.connect() as conexao:
                conexao.execute(text("ALTER TABLE usuarios ADD COLUMN reset_token VARCHAR"))
                conexao.commit()
        if 'session_token' not in colunas:
            with engine.connect() as conexao:
                conexao.execute(text("ALTER TABLE usuarios ADD COLUMN session_token VARCHAR"))
                conexao.commit()
except Exception as e:
    logger.warning(f"Aviso na verificacao de colunas: {e}")


def hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verificar_senha(senha: str, senha_hash: str) -> bool:
    if not senha_hash.startswith('$2b$') and not senha_hash.startswith('$2a$'):
        sha256_legado = hashlib.sha256(senha.encode()).hexdigest()
        return sha256_legado == senha_hash
    try:
        return bcrypt.checkpw(senha.encode('utf-8'), senha_hash.encode('utf-8'))
    except Exception:
        return False


def show_toast(mensagem: str, tipo: str = "info"):
    estilos = {"info": "rgba(14, 165, 233, 0.8)", "success": "rgba(16, 185, 129, 0.8)", "warning": "rgba(245, 158, 11, 0.8)", "error": "rgba(239, 68, 68, 0.8)"}
    st.markdown(f"""
    <div style="background-color: {estilos.get(tipo, 'rgba(14, 165, 233, 0.8)')}; backdrop-filter: blur(10px); padding: 12px 16px; border-radius: 8px; color: white; margin-bottom: 12px; font-weight: 500; font-size: 0.9rem; border: 1px solid rgba(255,255,255,0.1);">
        {mensagem}
    </div>
    """, unsafe_allow_html=True)


# --- CONTROLE DE SESSÃO COM AUTO-LOGIN ---
if "user_id" not in st.session_state: 
    st.session_state.user_id = None
if "username" not in st.session_state: 
    st.session_state.username = None
if "menu_ativo" not in st.session_state: 
    st.session_state.menu_ativo = "Visão Geral"

if st.session_state.user_id is None:
    token_url = st.query_params.get("session", None)
    if token_url:
        with get_db() as db:
            user_encontrado = db.query(Usuario).filter(Usuario.session_token == token_url).first()
            if user_encontrado:
                st.session_state.user_id = user_encontrado.id
                st.session_state.username = user_encontrado.username


# --- TELA DE AUTENTICAÇÃO ---
if st.session_state.user_id is None:
    st.markdown("<br>", unsafe_allow_html=True)
    col_esquerda, col_espaco, col_direita = st.columns([1.3, 0.2, 1.2])
    
    with col_esquerda:
        st.markdown("""
<div style='margin-top: 2vh;'>
    <div style='display: flex; align-items: center; gap: 8px; margin-bottom: 2rem;'>
        <span style='background: #2563eb; color: white; padding: 4px 8px; border-radius: 6px; font-weight: 700; font-size: 0.8rem;'>LP</span>
        <span style='color: rgba(255,255,255,0.8); font-weight: 500; font-size: 0.95rem;'>Lucid Productive</span>
    </div>
    <h1 style='font-weight: 700; font-size: 3.2rem; letter-spacing: -0.04em; color: #ffffff; line-height: 1.1; margin-bottom: 1.5rem;'>
        Clareza mental,<br>do primeiro<br>pensamento<br>à entrega.
    </h1>
    <p style='font-weight: 400; font-size: 0.95rem; color: rgba(255,255,255,0.5); line-height: 1.6; margin-bottom: 2.5rem; max-width: 420px;'>
        Sem distrações. Você sabe exatamente o que precisa ser feito — quadro, caderno, métricas e foco em um único ambiente.
    </p>
</div>
""", unsafe_allow_html=True)
        
        st.markdown("<div style='border-top: 1px solid rgba(255,255,255,0.08); margin-bottom: 1.5rem;'></div>", unsafe_allow_html=True)
        
        c_inf1, c_inf2, c_inf3 = st.columns(3)
        with c_inf1:
            st.markdown("<div style='color: #ffffff; font-weight: 600; font-size: 0.9rem; margin-bottom: 2px;'>Quadro</div><div style='color: rgba(255,255,255,0.4); font-size: 0.75rem;'>Kanban com subtarefas</div>", unsafe_allow_html=True)
        with c_inf2:
            st.markdown("<div style='color: #ffffff; font-weight: 600; font-size: 0.9rem; margin-bottom: 2px;'>Caderno</div><div style='color: rgba(255,255,255,0.4); font-size: 0.75rem;'>Documentos com tags</div>", unsafe_allow_html=True)
        with c_inf3:
            st.markdown("<div style='color: #ffffff; font-weight: 600; font-size: 0.9rem; margin-bottom: 2px;'>Foco</div><div style='color: rgba(255,255,255,0.4); font-size: 0.75rem;'>Ciclos pomodoro</div>", unsafe_allow_html=True)
        
    with col_direita:
        st.markdown("<br>", unsafe_allow_html=True)
        aba_login, aba_cadastro, aba_reset = st.tabs(["Entrar", "Criar conta", "Recuperar"])
        
        with aba_login:
            with st.form("form_login_auth"):
                user_input = st.text_input("Usuário")
                senha_input = st.text_input("Senha", type="password")
                if st.form_submit_button("Entrar no workspace"):
                    with get_db() as db:
                        user_db = db.query(Usuario).filter(Usuario.username == user_input).first()
                        if user_db and verificar_senha(senha_input, user_db.senha_hash):
                            novo_token_sessao = str(uuid.uuid4())
                            user_db.session_token = novo_token_sessao
                            db.commit()
                            
                            st.session_state.user_id = user_db.id
                            st.session_state.username = user_db.username
                            st.query_params["session"] = novo_token_sessao
                            st.rerun()
                        else:
                            st.error("Usuário ou senha incorretos.")
                            
        with aba_cadastro:
            with st.form("form_cadastro_auth"):
                novo_user = st.text_input("Escolha um Usuário")
                nova_senha = st.text_input("Escolha uma Senha", type="password")
                if st.form_submit_button("Criar conta"):
                    if not novo_user or not nova_senha:
                        st.warning("Preencha todos os campos.")
                    else:
                        with get_db() as db:
                            if db.query(Usuario).filter(Usuario.username == novo_user).first():
                                st.error("Usuário já existe.")
                            else:
                                db.add(Usuario(username=novo_user, senha_hash=hash_senha(nova_senha)))
                                db.commit()
                                st.success("Conta criada! Vá para a aba Entrar.")

        with aba_reset:
            with st.form("form_reset_auth"):
                u_reset = st.text_input("Usuário")
                if st.form_submit_button("Gerar Token"):
                    with get_db() as db:
                        u_db = db.query(Usuario).filter(Usuario.username == u_reset).first()
                        if u_db:
                            token = str(uuid.uuid4())[:8].upper()
                            u_db.reset_token = token
                            db.commit()
                            st.info(f"Token gerado para {u_reset}. Verifique o painel Admin.")
                        else:
                            st.error("Usuário não encontrado.")
                
                t_input = st.text_input("Token")
                new_s = st.text_input("Nova Senha", type="password")
                if st.form_submit_button("Redefinir Senha"):
                    with get_db() as db:
                        u_db = db.query(Usuario).filter(Usuario.username == u_reset).first()
                        if u_db and u_db.reset_token and u_db.reset_token == t_input.strip():
                            u_db.senha_hash = hash_senha(new_s)
                            u_db.reset_token = None
                            db.commit()
                            st.success("Senha alterada com sucesso!")
                        else:
                            st.error("Token ou usuário inválidos.")
    st.stop()

user_id = st.session_state.user_id

# --- SIDEBAR ---
st.sidebar.markdown("### Lucid Productive")
st.sidebar.caption(f"Workspace: **{st.session_state.username}**")

with get_db() as db:
    notificacoes_usuario = db.query(Notificacao).filter(Notificacao.usuario_id == user_id, Notificacao.lida == False).all()
    num_notif = len(notificacoes_usuario)
    titulo_notif = f"Notificações ({num_notif})" if num_notif > 0 else "Notificações"

    with st.sidebar.expander(titulo_notif):
        if not notificacoes_usuario:
            st.write("Nenhum alerta pendente.")
        else:
            for notif in notificacoes_usuario:
                st.info(notif.mensagem)
            if st.button("Marcar todas como lidas"):
                for notif in notificacoes_usuario:
                    notif.lida = True
                db.commit()
                st.rerun()

menu_opcoes = ["Visão Geral", "Gerenciador de Tarefas", "Caderno e Tópicos", "Estatísticas"]
if st.session_state.username == "lucasmurpf":
    menu_opcoes.append("Painel Admin")

if st.session_state.menu_ativo not in menu_opcoes:
    st.session_state.menu_ativo = "Visão Geral"

menu_selecionado = st.sidebar.radio(
    "Navegação:", 
    menu_opcoes, 
    index=menu_opcoes.index(st.session_state.menu_ativo)
)
st.session_state.menu_ativo = menu_selecionado
menu = menu_selecionado

if st.sidebar.button("Encerrar Sessão"):
    with get_db() as db:
        if st.session_state.user_id:
            u_sair = db.query(Usuario).filter(Usuario.id == st.session_state.user_id).first()
            if u_sair:
                u_sair.session_token = None
                db.commit()
                
    st.session_state.user_id = None
    st.session_state.username = None
    st.session_state.menu_ativo = "Visão Geral"
    st.query_params.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("Pomodoro Foco")
tempo_foco = st.sidebar.selectbox("Duração (min):", [25, 30, 45, 50], index=0)

# Estados do Pomodoro
if "pomodoro_fim" not in st.session_state:
    st.session_state.pomodoro_fim = None
if "pomodoro_total" not in st.session_state:
    st.session_state.pomodoro_total = tempo_foco * 60
if "arvore_status" not in st.session_state:
    st.session_state.arvore_status = "neutra"  # "neutra", "crescendo", "viva", "morta"

col_p1, col_p2 = st.sidebar.columns(2)
if col_p1.button("Iniciar"):
    st.session_state.pomodoro_total = tempo_foco * 60
    st.session_state.pomodoro_fim = time.time() + st.session_state.pomodoro_total
    st.session_state.arvore_status = "crescendo"
    st.rerun()

if col_p2.button("Desistir"):
    if st.session_state.pomodoro_fim is not None:
        st.session_state.arvore_status = "morta"
    st.session_state.pomodoro_fim = None
    st.rerun()

# Renderizador de Árvore SVG e Timer
@st.fragment(run_every=1)
def render_pomodoro_e_arvore():
    fim = st.session_state.pomodoro_fim
    total = st.session_state.pomodoro_total or (25 * 60)
    status = st.session_state.arvore_status

    if fim:
        restante = int(fim - time.time())
        if restante > 0:
            progresso = 1.0 - (restante / total)
            m, sec = divmod(restante, 60)
            
            # Cálculo de estágios da árvore (0.0 até 1.0)
            altura_tronco = 10 + (progresso * 35) # de 10 a 45px
            raio_folha_base = max(0, (progresso - 0.25) / 0.75) * 26 # nasce após 25%
            raio_folha_topo = max(0, (progresso - 0.50) / 0.50) * 18 # nasce após 50%
            
            svg_arvore = f"""
            <svg width="100%" height="110" viewBox="0 0 140 110" style="display: block; margin: auto;">
                <!-- Linha de solo -->
                <line x1="20" y1="95" x2="120" y2="95" stroke="rgba(255,255,255,0.15)" stroke-width="2" stroke-linecap="round" />
                
                <!-- Broto / Tronco -->
                <line x1="70" y1="95" x2="70" y2="{95 - altura_tronco}" stroke="#854d0e" stroke-width="{3 + progresso * 3}" stroke-linecap="round" />
                
                <!-- Ramos intermediários -->
                {f'<line x1="70" y1="75" x2="58" y2="65" stroke="#854d0e" stroke-width="3" stroke-linecap="round" />' if progresso > 0.4 else ''}
                {f'<line x1="70" y1="70" x2="82" y2="60" stroke="#854d0e" stroke-width="3" stroke-linecap="round" />' if progresso > 0.4 else ''}
                
                <!-- Copa das folhas -->
                {f'<circle cx="70" cy="55" r="{raio_folha_base}" fill="#16a34a" fill-opacity="0.85" />' if raio_folha_base > 0 else ''}
                {f'<circle cx="56" cy="58" r="{raio_folha_base * 0.75}" fill="#15803d" fill-opacity="0.9" />' if raio_folha_base > 0 else ''}
                {f'<circle cx="84" cy="58" r="{raio_folha_base * 0.75}" fill="#15803d" fill-opacity="0.9" />' if raio_folha_base > 0 else ''}
                {f'<circle cx="70" cy="40" r="{raio_folha_topo}" fill="#22c55e" fill-opacity="0.95" />' if raio_folha_topo > 0 else ''}
                
                <!-- Semente inicial -->
                {f'<ellipse cx="70" cy="94" rx="4" ry="2.5" fill="#a16207" />' if progresso <= 0.25 else ''}
            </svg>
            """
            
            st.markdown(f"""
            <div style='background: rgba(17, 24, 39, 0.6); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 12px; margin-top: 10px;'>
                {svg_arvore}
                <div style='text-align: center; font-size: 1.4rem; font-weight: 700; color: #ffffff; letter-spacing: 0.05em; margin-top: 4px;'>{m:02d}:{sec:02d}</div>
                <div style='text-align: center; font-size: 0.75rem; color: rgba(255,255,255,0.4); margin-top: 2px;'>Mantenha o foco para a árvore crescer ({int(progresso * 100)}%)</div>
            </div>
            """, unsafe_allow_html=True)
            
        else:
            st.session_state.pomodoro_fim = None
            st.session_state.arvore_status = "viva"
            st.rerun()

    elif status == "viva":
        # Árvore adulta e florida após cumprir o tempo
        svg_arvore_viva = """
        <svg width="100%" height="110" viewBox="0 0 140 110" style="display: block; margin: auto;">
            <line x1="20" y1="95" x2="120" y2="95" stroke="#16a34a" stroke-width="2" stroke-linecap="round" />
            <line x1="70" y1="95" x2="70" y2="50" stroke="#854d0e" stroke-width="6" stroke-linecap="round" />
            <circle cx="70" cy="50" r="28" fill="#16a34a" fill-opacity="0.9" />
            <circle cx="52" cy="55" r="22" fill="#15803d" fill-opacity="0.9" />
            <circle cx="88" cy="55" r="22" fill="#15803d" fill-opacity="0.9" />
            <circle cx="70" cy="35" r="20" fill="#22c55e" fill-opacity="0.95" />
            <!-- Flores -->
            <circle cx="58" cy="45" r="3" fill="#f43f5e" />
            <circle cx="82" cy="48" r="3" fill="#f43f5e" />
            <circle cx="70" cy="28" r="3.5" fill="#facc15" />
        </svg>
        """
        st.markdown(f"""
        <div style='background: rgba(22, 163, 74, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 12px; padding: 12px; margin-top: 10px;'>
            {svg_arvore_viva}
            <div style='text-align: center; font-size: 0.9rem; font-weight: 600; color: #4ade80; margin-top: 4px;'>Ciclo completo! Árvore salva.</div>
        </div>
        """, unsafe_allow_html=True)

    elif status == "morta":
        # Árvore seca / morta caso tenha cancelado
        svg_arvore_morta = """
        <svg width="100%" height="110" viewBox="0 0 140 110" style="display: block; margin: auto;">
            <line x1="20" y1="95" x2="120" y2="95" stroke="#ef4444" stroke-width="2" stroke-linecap="round" />
            <!-- Tronco e galhos secos -->
            <line x1="70" y1="95" x2="70" y2="55" stroke="#52525b" stroke-width="4" stroke-linecap="round" />
            <line x1="70" y1="75" x2="52" y2="60" stroke="#52525b" stroke-width="2.5" stroke-linecap="round" />
            <line x1="70" y1="68" x2="88" y2="58" stroke="#52525b" stroke-width="2.5" stroke-linecap="round" />
            <line x1="52" y1="60" x2="44" y2="68" stroke="#52525b" stroke-width="1.5" stroke-linecap="round" />
            <line x1="88" y1="58" x2="96" y2="65" stroke="#52525b" stroke-width="1.5" stroke-linecap="round" />
            <!-- Folha caída -->
            <ellipse cx="80" cy="93" rx="4" ry="2" fill="#71717a" />
        </svg>
        """
        st.markdown(f"""
        <div style='background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 12px; padding: 12px; margin-top: 10px;'>
            {svg_arvore_morta}
            <div style='text-align: center; font-size: 0.85rem; font-weight: 600; color: #f87171; margin-top: 4px;'>Você desistiu. A árvore secou.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Estado inicial / neutro
        svg_arvore_neutra = """
        <svg width="100%" height="80" viewBox="0 0 140 80" style="display: block; margin: auto; opacity: 0.3;">
            <line x1="30" y1="65" x2="110" y2="65" stroke="#ffffff" stroke-width="2" stroke-linecap="round" />
            <circle cx="70" cy="64" r="3" fill="#ffffff" />
        </svg>
        """
        st.markdown(f"""
        <div style='background: rgba(255,255,255,0.02); border: 1px dashed rgba(255,255,255,0.1); border-radius: 12px; padding: 10px; margin-top: 10px;'>
            {svg_arvore_neutra}
            <div style='text-align: center; font-size: 0.75rem; color: rgba(255,255,255,0.3);'>Inicie o ciclo para plantar sua árvore</div>
        </div>
        """, unsafe_allow_html=True)

with st.sidebar:
    render_pomodoro_e_arvore()


# --- CONTEÚDO PRINCIPAL ---
with get_db() as db:
    sub_ids_usuario = [s.tarefa_id for s in db.query(SubTarefa).filter(SubTarefa.responsavel_id == user_id).all()]
    usuarios_cadastrados = db.query(Usuario).all()
    dict_usuarios = {u.username: u.id for u in usuarios_cadastrados}
    lista_usernames = list(dict_usuarios.keys())
    idx_usuario_logado = lista_usernames.index(st.session_state.username) if st.session_state.username in lista_usernames else 0

if menu == "Painel Admin":
    st.title("Painel Administrativo")
    st.markdown("Gerenciamento de solicitações de redefinição de senha.")
    with get_db() as db:
        users = db.query(Usuario).filter(Usuario.reset_token != None).all()
        if users:
            data = [{"Usuário": u.username, "Token de Reset": u.reset_token} for u in users]
            st.table(pd.DataFrame(data))
        else:
            st.info("Nenhum token de recuperação pendente no momento.")

elif menu == "Visão Geral":
    st.title("Painel Executivo")
    st.markdown("Acompanhe o panorama geral das suas demandas e produtividade.")

    with get_db() as db:
        total_tarefas = db.query(Tarefa).filter((Tarefa.responsavel_id == user_id) | (Tarefa.criador_id == user_id) | (Tarefa.id.in_(sub_ids_usuario))).count()
        tarefas_concluidas = db.query(Tarefa).filter((((Tarefa.responsavel_id == user_id) | (Tarefa.criador_id == user_id) | (Tarefa.id.in_(sub_ids_usuario))) & (Tarefa.concluida == True))).count()
        tarefas_pendentes = total_tarefas - tarefas_concluidas
        total_anotacoes = db.query(Anotacao).filter(Anotacao.usuario_id == user_id).count()

        tarefas_urgentes = db.query(Tarefa).filter(
            (Tarefa.responsavel_id == user_id) | (Tarefa.id.in_(sub_ids_usuario)), 
            Tarefa.concluida == False, 
            Tarefa.prazo != None
        ).order_by(Tarefa.prazo.asc()).limit(5).all()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total de Demandas", total_tarefas)
        col2.metric("Pendentes", tarefas_pendentes)
        col3.metric("Concluídas", tarefas_concluidas)
        col4.metric("Documentos", total_anotacoes)

        st.markdown("---")
        st.subheader("Vencimentos Próximos")
            
        if tarefas_urgentes:
            for t in tarefas_urgentes:
                criador_nome = t.criador.username if t.criador else "Desconhecido"
                
                st.markdown(f"""
                <div style="background-color: rgba(17, 19, 24, 0.4); padding: 14px 18px; border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.06); margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; backdrop-filter: blur(10px);">
                    <div>
                        <strong style="color: rgba(255,255,255,0.9); font-size: 0.95rem;">{t.titulo}</strong>
                        <div style="color: rgba(255,255,255,0.4); font-size: 0.8rem; margin-top: 2px;">
                            Criador: {criador_nome} | Prazo: {t.prazo.strftime('%d/%m/%Y')} | Prioridade: {t.prioridade}
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                if st.button(f"Ir para a tarefa: {t.titulo}", key=f"goto_{t.id}"):
                    st.session_state.menu_ativo = "Gerenciador de Tarefas"
                    st.rerun()
        else:
            st.info("Nenhuma demanda crítica pendente para os próximos dias.")

elif menu == "Gerenciador de Tarefas":
    st.title("Quadro Kanban")

    with st.expander("Criar Nova Demanda", expanded=False):
        with st.form("form_tarefa", clear_on_submit=True):
            col_f1, col_f2, col_f3, col_f4 = st.columns([0.35, 0.25, 0.2, 0.2])
            novo_titulo = col_f1.text_input("Título da Demanda")
            resp_escolhido = col_f2.selectbox("Responsável", lista_usernames, index=idx_usuario_logado)
            prioridade = col_f3.selectbox("Prioridade", ["Baixa", "Média", "Alta", "Urgente"], index=1)
            prazo = col_f4.date_input("Prazo Limite", value=date.today(), format="DD/MM/YYYY")
            
            submitted = st.form_submit_button("Cadastrar")
            if submitted and novo_titulo:
                with get_db() as db_create:
                    id_resp = dict_usuarios[resp_escolhido]
                    nova = Tarefa(
                        titulo=novo_titulo, 
                        status_kanban="A Fazer",
                        prioridade=prioridade, 
                        prazo=prazo, 
                        criador_id=user_id,
                        responsavel_id=id_resp
                    )
                    db_create.add(nova)
                    
                    if id_resp != user_id:
                        notif = Notificacao(mensagem=f"Nova demanda atribuída por {st.session_state.username}: '{novo_titulo}'", usuario_id=id_resp)
                        db_create.add(notif)
                    db_create.commit()
                
                show_toast(f"Demanda '{novo_titulo}' criada com sucesso.", "success")
                st.rerun()

    st.markdown("---")

    with get_db() as db:
        query_tarefas = db.query(Tarefa).filter(
            (Tarefa.responsavel_id == user_id) | (Tarefa.criador_id == user_id) | (Tarefa.id.in_(sub_ids_usuario))
        )
        tarefas = query_tarefas.all()

        if not tarefas:
            st.info("Nenhuma demanda registrada no momento.")
        else:
            col_k1, col_k2, col_k3 = st.columns(3)
            colunas_dados = [
                ("A Fazer", "A Fazer", col_k1),
                ("Em Andamento", "Em Andamento", col_k2),
                ("Concluído", "Concluído", col_k3)
            ]

            for nome_col, status_filtro, coluna_ui in colunas_dados:
                with coluna_ui:
                    st.subheader(nome_col)
                    tarefas_filtradas = [t for t in tarefas if t.status_kanban == status_filtro]
                    
                    for t in tarefas_filtradas:
                        sub_conc = len([s for s in t.subtarefas if s.concluida])
                        sub_tot = len(t.subtarefas)
                        
                        with st.expander(f"{t.titulo} ({sub_conc}/{sub_tot})"):
                            resp_nome = t.responsavel_user.username if t.responsavel_user else "N/A"
                            criador_nome = t.criador.username if t.criador else "N/A"
                            prazo_str = t.prazo.strftime('%d/%m/%Y') if t.prazo else "Sem prazo"
                            
                            st.caption(f"Resp: {resp_nome} | Criador: {criador_nome}")
                            st.caption(f"Vencimento: {prazo_str} | Prioridade: {t.prioridade}")
                            
                            novo_status = st.selectbox(
                                "Mover Status:", 
                                ["A Fazer", "Em Andamento", "Concluído"], 
                                index=["A Fazer", "Em Andamento", "Concluído"].index(t.status_kanban),
                                key=f"status_{t.id}"
                            )
                            if novo_status != t.status_kanban:
                                t.status_kanban = novo_status
                                t.concluida = True if novo_status == "Concluído" else False
                                db.commit()
                                st.rerun()

                            # --- EDIÇÃO DA TAREFA ---
                            with st.expander("Editar Demanda", expanded=False):
                                with st.form(key=f"edit_task_form_{t.id}"):
                                    edit_tit = st.text_input("Título", value=t.titulo, key=f"et_tit_{t.id}")
                                    c_et1, c_et2, c_et3 = st.columns(3)
                                    
                                    resp_idx = lista_usernames.index(resp_nome) if resp_nome in lista_usernames else idx_usuario_logado
                                    edit_resp = c_et1.selectbox("Responsável", lista_usernames, index=resp_idx, key=f"et_resp_{t.id}")
                                    
                                    prios = ["Baixa", "Média", "Alta", "Urgente"]
                                    prio_idx = prios.index(t.prioridade) if t.prioridade in prios else 1
                                    edit_prio = c_et2.selectbox("Prioridade", prios, index=prio_idx, key=f"et_prio_{t.id}")
                                    
                                    edit_pz = c_et3.date_input("Prazo", value=t.prazo if t.prazo else date.today(), format="DD/MM/YYYY", key=f"et_pz_{t.id}")

                                    if st.form_submit_button("Salvar Alterações"):
                                        t.titulo = edit_tit
                                        t.responsavel_id = dict_usuarios[edit_resp]
                                        t.prioridade = edit_prio
                                        t.prazo = edit_pz
                                        db.commit()
                                        show_toast("Demanda atualizada.", "success")
                                        st.rerun()

                            st.markdown("---")
                            
                            # --- SUBTAREFAS (DESIGN MINIMALISTA E LINEAR) ---
                            if t.subtarefas:
                                st.markdown("**Subtarefas:**")
                                for sub in t.subtarefas:
                                    resp_sub_nome = sub.responsavel_sub.username if sub.responsavel_sub else "-"
                                    sub_p = sub.prazo.strftime('%d/%m/%Y') if sub.prazo else "-"
                                    
                                    concluiu_sub = st.checkbox(
                                        f"{sub.titulo}  •  {resp_sub_nome}  •  {sub_p}", 
                                        value=sub.concluida, 
                                        key=f"sub_{sub.id}"
                                    )
                                    if concluiu_sub != sub.concluida:
                                        sub.concluida = concluiu_sub
                                        db.commit()
                                        st.rerun()

                                    with st.expander("Opções da subtarefa", expanded=False):
                                        with st.form(key=f"form_edit_sub_{sub.id}"):
                                            sub_e_tit = st.text_input("Título", value=sub.titulo, key=f"es_tit_{sub.id}")
                                            ces_1, ces_2 = st.columns(2)
                                            sub_r_idx = lista_usernames.index(resp_sub_nome) if resp_sub_nome in lista_usernames else idx_usuario_logado
                                            sub_e_resp = ces_1.selectbox("Responsável", lista_usernames, index=sub_r_idx, key=f"es_resp_{sub.id}")
                                            sub_e_pz = ces_2.date_input("Prazo", value=sub.prazo if sub.prazo else date.today(), format="DD/MM/YYYY", key=f"es_pz_{sub.id}")
                                            
                                            if st.form_submit_button("Salvar Modificações"):
                                                sub.titulo = sub_e_tit
                                                sub.responsavel_id = dict_usuarios[sub_e_resp]
                                                sub.prazo = sub_e_pz
                                                db.commit()
                                                st.rerun()
                                        
                                        if st.button("Excluir subtarefa", key=f"del_sub_{sub.id}"):
                                            db.delete(sub)
                                            db.commit()
                                            st.rerun()

                                    if sub.imagem_base64:
                                        try:
                                            img_bytes = base64.b64decode(sub.imagem_base64)
                                            st.image(img_bytes, caption="Anexo", use_column_width=True)
                                        except Exception:
                                            pass

                            with st.expander("Adicionar Subtarefa", expanded=False):
                                with st.form(key=f"form_sub_{t.id}", clear_on_submit=True):
                                    st_tit = st.text_input("Título", key=f"tit_sub_{t.id}")
                                    cs_1, cs_2 = st.columns(2)
                                    st_pz = cs_1.date_input("Prazo", value=date.today(), format="DD/MM/YYYY", key=f"pz_sub_{t.id}")
                                    st_resp = cs_2.selectbox("Responsável", lista_usernames, index=idx_usuario_logado, key=f"resp_sub_{t.id}")
                                    st_img = st.file_uploader("Anexo (Opcional)", type=["png", "jpg", "jpeg"], key=f"img_sub_{t.id}")

                                    if st.form_submit_button("Criar Subtarefa") and st_tit:
                                        img_sub_b64 = None
                                        if st_img is not None:
                                            img_sub_b64 = base64.b64encode(st_img.read()).decode("utf-8")

                                        id_resp_sub = dict_usuarios[st_resp]
                                        
                                        with get_db() as db_sub:
                                            nova_sub = SubTarefa(
                                                titulo=st_tit, 
                                                prazo=st_pz, 
                                                responsavel_id=id_resp_sub,
                                                imagem_base64=img_sub_b64,
                                                tarefa_id=t.id
                                            )
                                            db_sub.add(nova_sub)
                                            
                                            if id_resp_sub != user_id:
                                                notif_sub = Notificacao(mensagem=f"Subtarefa atribuída por {st.session_state.username}: '{st_tit}'", usuario_id=id_resp_sub)
                                                db_sub.add(notif_sub)
                                            db_sub.commit()
                                        st.rerun()

                            st.markdown("---")
                            confirm_key = f"confirm_del_task_{t.id}"
                            if not st.session_state.get(confirm_key, False):
                                if st.button("Remover Demanda", key=f"btn_rem_{t.id}"):
                                    st.session_state[confirm_key] = True
                                    st.rerun()
                            else:
                                st.warning("Tem certeza?")
                                col_y, col_n = st.columns(2)
                                if col_y.button("Sim, remover", key=f"yes_rem_{t.id}"):
                                    db.delete(t)
                                    db.commit()
                                    st.session_state[confirm_key] = False
                                    st.rerun()
                                if col_n.button("Cancelar", key=f"no_rem_{t.id}"):
                                    st.session_state[confirm_key] = False
                                    st.rerun()

elif menu == "Caderno e Tópicos":
    st.title("Repositório de Conhecimento")

    with get_db() as db:
        todas_notas = db.query(Anotacao).filter(Anotacao.usuario_id == user_id).all()
        tags_unicas = sorted(list(set(tag.strip() for nota in todas_notas if nota.tags for tag in nota.tags.split(","))))

    col_s1, col_s2 = st.columns([0.7, 0.3])
    busca = col_s1.text_input("Pesquisar base...", placeholder="Digite termos...")
    filtro_tag = col_s2.selectbox("Filtrar Tag", ["Todas"] + tags_unicas)

    with st.expander("Criar Nova Documentação"):
        with st.form("form_anotacao_pro"):
            titulo_novo = st.text_input("Título do Documento")
            tags_novo = st.text_input("Tags (separadas por vírgula)")
            conteudo_novo = st.text_area("Conteúdo Técnico (Markdown)", height=150)
            imagem_upload = st.file_uploader("Evidência Gráfica", type=["png", "jpg", "jpeg"])
            
            if imagem_upload is not None:
                st.image(imagem_upload, caption="Pré-visualização", width=200)

            if st.form_submit_button("Salvar Documentação"):
                if titulo_novo:
                    with get_db() as db:
                        img_b64 = base64.b64encode(imagem_upload.read()).decode("utf-8") if imagem_upload else None
                        tags_formatadas = ",".join([t.strip().upper() for t in tags_novo.split(",")]) if tags_novo else "GERAL"
                        
                        nova_nota = Anotacao(
                            titulo=titulo_novo, 
                            tags=tags_formatadas, 
                            conteudo=conteudo_novo, 
                            imagem_base64=img_b64,
                            usuario_id=user_id
                        )
                        db.add(nova_nota)
                        db.commit()
                    show_toast("Documentação salva com sucesso.", "success")
                    st.rerun()
                else:
                    st.error("O título do documento é obrigatório.")

    st.markdown("---")

    with get_db() as db:
        query_notas = db.query(Anotacao).filter(Anotacao.usuario_id == user_id)
        if busca:
            query_notas = query_notas.filter(Anotacao.conteudo.contains(busca) | Anotacao.titulo.contains(busca))
        anotacoes = query_notas.order_by(Anotacao.data_criacao.desc()).all()

        if filtro_tag != "Todas":
            anotacoes = [n for n in anotacoes if n.tags and filtro_tag in [t.strip() for t in n.tags.split(",")]]

        if not anotacoes:
            st.info("Nenhuma documentação encontrada.")
        else:
            for nota in anotacoes:
                with st.expander(nota.titulo, expanded=False):
                    st.caption(f"Criado em: {nota.data_criacao.strftime('%d/%m/%Y %H:%M')}")
                    
                    if nota.tags:
                        badges = "".join([f"<span style='background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.8); padding: 4px 10px; border-radius: 12px; font-size: 0.7em; margin-right: 6px; border: 1px solid rgba(255,255,255,0.05);'>{t}</span>" for t in nota.tags.split(",")])
                        st.markdown(badges, unsafe_allow_html=True)
                        st.markdown("<br>", unsafe_allow_html=True)

                    if nota.conteudo:
                        st.markdown(nota.conteudo)

                    if nota.imagem_base64:
                        try:
                            st.image(base64.b64decode(nota.imagem_base64), caption="Anexo", use_column_width=True)
                        except Exception:
                            pass

                    st.markdown("---")
                    
                    # --- EDIÇÃO DE DOCUMENTOS ---
                    with st.expander("Editar Documentação", expanded=False):
                        with st.form(key=f"form_edit_note_{nota.id}"):
                            edit_not_tit = st.text_input("Título", value=nota.titulo, key=f"en_tit_{nota.id}")
                            edit_not_tags = st.text_input("Tags", value=nota.tags, key=f"en_tags_{nota.id}")
                            edit_not_cont = st.text_area("Conteúdo", value=nota.conteudo or "", height=150, key=f"en_cont_{nota.id}")
                            
                            if st.form_submit_button("Salvar Alterações"):
                                nota.titulo = edit_not_tit
                                nota.tags = ",".join([t.strip().upper() for t in edit_not_tags.split(",")]) if edit_not_tags else "GERAL"
                                nota.conteudo = edit_not_cont
                                db.commit()
                                show_toast("Documento atualizado com sucesso.", "success")
                                st.rerun()

                    confirm_k_nota = f"del_nota_{nota.id}"
                    if not st.session_state.get(confirm_k_nota, False):
                        if st.button("Excluir Documento", key=f"btn_nota_{nota.id}"):
                            st.session_state[confirm_k_nota] = True
                            st.rerun()
                    else:
                        st.warning("Remover documento?")
                        c_y, c_n = st.columns(2)
                        if c_y.button("Sim", key=f"y_nota_{nota.id}"):
                            n_del = db.query(Anotacao).filter_by(id=nota.id).first()
                            db.delete(n_del)
                            db.commit()
                            st.session_state[confirm_k_nota] = False
                            st.rerun()
                        if c_n.button("Não", key=f"n_nota_{nota.id}"):
                            st.session_state[confirm_k_nota] = False
                            st.rerun()

elif menu == "Estatísticas":
    st.title("Métricas de Desempenho")
    st.markdown("Análise quantitativa de volume e distribuição de prioridades.")
    
    with get_db() as db:
        tarefas_df = pd.read_sql(db.query(Tarefa).filter((Tarefa.responsavel_id == user_id) | (Tarefa.criador_id == user_id) | (Tarefa.id.in_(sub_ids_usuario))).statement, db.bind)
    
    if not tarefas_df.empty:
        st.subheader("Distribuição por Nível de Prioridade")
        prioridade_counts = tarefas_df['prioridade'].value_counts()
        st.bar_chart(prioridade_counts)
    else:
        st.info("Insira demandas para gerar os gráficos analíticos.")
