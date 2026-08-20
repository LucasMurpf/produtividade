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

# --- DESIGN SYSTEM & TOKENS DE ESTILO (LAYOUT DUPLA COLUNA) ---
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
        padding: 0.6rem 1rem;
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
        db.commit()
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

# Migração segura de coluna
try:
    inspector = inspect(engine)
    if 'usuarios' in inspector.get_table_names():
        colunas = [col['name'] for col in inspector.get_columns('usuarios')]
        if 'reset_token' not in colunas:
            with engine.connect() as conexao:
                conexao.execute(text("ALTER TABLE usuarios ADD COLUMN reset_token VARCHAR"))
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


# --- CONTROLE DE SESSÃO ---
if "user_id" not in st.session_state: 
    st.session_state.user_id = None
if "username" not in st.session_state: 
    st.session_state.username = None
if "menu_ativo" not in st.session_state: 
    st.session_state.menu_ativo = "Visão Geral"


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
                            st.session_state.user_id = user_db.id
                            st.session_state.username = user_db.username
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
                            st.success("Senha alterada com sucesso!")
                        else:
                            st.error("Token ou usuário inválidos.")
    st.stop()

user_id = st.session_state.user_id

# --- SIDEBAR (NAVEGAÇÃO COM SINCRONIZAÇÃO NATIVA) ---
st.sidebar.markdown(f"### Lucid Productive")
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
                st.rerun()

menu_opcoes = ["Visão Geral", "Gerenciador de Tarefas", "Caderno e Tópicos", "Estatísticas"]
if st.session_state.username == "lucasmurpf":
    menu_opcoes.append("Painel Admin")

if st.session_state.menu_ativo not in menu_opcoes:
    st.session_state.menu_ativo = "Visão Geral"

menu = st.sidebar.radio(
    "Navegação:", 
    menu_opcoes, 
    key="menu_ativo"
)

if st.sidebar.button("Encerrar Sessão"):
    st.session_state.user_id = None
    st.session_state.username = None
    st.session_state.menu_ativo = "Visão Geral"
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("Pomodoro Foco")
tempo_foco = st.sidebar.selectbox("Duração (min):", [25, 30, 45, 50], index=0)

if "pomodoro_fim" not in st.session_state:
    st.session_state.pomodoro_fim = None

col_p1, col_p2 = st.sidebar.columns(2)
if col_p1.button("Iniciar"):
    st.session_state.pomodoro_fim = time.time() + (tempo_foco * 60)
    st.rerun()
if col_p2.button("Parar"):
    st.session_state.pomodoro_fim = None
    st.rerun()

@st.fragment(run_every=1)
def render_pomodoro_timer():
    if st.session_state.pomodoro_fim:
        tempo_restante = int(st.session_state.pomodoro_fim - time.time())
        if tempo_restante > 0:
            m, sec = divmod(tempo_restante, 60)
            st.markdown(
                f"<div style='text-align: center; color: rgba(255,255,255,0.9); background: rgba(255,255,255,0.05); padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); font-size: 1.2rem;'><b>{m:02d}:{sec:02d}</b></div>", 
                unsafe_allow_html=True
            )
        else:
            st.session_state.pomodoro_fim = None
            st.success("Foco concluído")
            st.rerun()

with st.sidebar:
    render_pomodoro_timer()


# --- CONTEÚDO PRINCIPAL ---
with get_db() as db:
    sub_ids_usuario = [s.tarefa_id for s in db.query(SubTarefa).filter(SubTarefa.responsavel_id == user_id).all()]

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

    with get_db() as db:
        usuarios_cadastrados = db.query(Usuario).all()
        dict_usuarios = {u.username: u.id for u in usuarios_cadastrados}

    with st.expander("Criar Nova Demanda", expanded=False):
        with st.form("form_tarefa", clear_on_submit=True):
            col_f1, col_f2, col_f3, col_f4 = st.columns([0.35, 0.25, 0.2, 0.2])
            novo_titulo = col_f1.text_input("Título da Demanda")
            resp_escolhido = col_f2.selectbox("Responsável", list(dict_usuarios.keys()), index=list(dict_usuarios.keys()).index(st.session_state.username) if st.session_state.username in dict_usuarios else 0)
            prioridade = col_f3.selectbox("Prioridade", ["Baixa", "Média", "Alta", "Urgente"])
            prazo = col_f4.date_input("Prazo Limite", value=date.today())
            
            submitted = st.form_submit_button("Cadastrar")
            if submitted and novo_titulo:
                with get_db() as db:
                    id_resp = dict_usuarios[resp_escolhido]
                    nova = Tarefa(
                        titulo=novo_titulo, 
                        status_kanban="A Fazer",
                        prioridade=prioridade, 
                        prazo=prazo, 
                        criador_id=user_id,
                        responsavel_id=id_resp
                    )
                    db.add(nova)
                    db.flush()
                    
                    if id_resp != user_id:
                        notif = Notificacao(mensagem=f"Nova demanda atribuída por {st.session_state.username}: '{novo_titulo}'", usuario_id=id_resp)
                        db.add(notif)
                
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
                                "Status:", 
                                ["A Fazer", "Em Andamento", "Concluído"], 
                                index=["A Fazer", "Em Andamento", "Concluído"].index(t.status_kanban),
                                key=f"status_{t.id}"
                            )
                            if novo_status != t.status_kanban:
                                t.status_kanban = novo_status
                                t.concluida = True if novo_status == "Concluído" else False
                                st.rerun()

                            st.markdown("---")
                            
                            if t.subtarefas:
                                st.markdown("**Subtarefas:**")
                                for sub in t.subtarefas:
                                    c_s1, c_s2, c_s3 = st.columns([0.5, 0.35, 0.15])
                                    concluiu_sub = c_s1.checkbox(sub.titulo, value=sub.concluida, key=f"sub_{sub.id}")
                                    if concluiu_sub != sub.concluida:
                                        sub.concluida = concluiu_sub
                                        db.commit()
                                        st.rerun()
                                    
                                    resp_sub_nome = sub.responsavel_sub.username if sub.responsavel_sub else "Sem resp."
                                    sub_p = sub.prazo.strftime('%d/%m/%Y') if sub.prazo else "-"
                                    c_s2.markdown(f"<span style='font-size: 0.8em; color: rgba(255,255,255,0.5);'>Resp: {resp_sub_nome} <br>Prazo: {sub_p}</span>", unsafe_allow_html=True)
                                    
                                    if c_s3.button("X", key=f"del_sub_{sub.id}"):
                                        db.delete(sub)
                                        db.commit()
                                        st.rerun()

                                    if sub.imagem_base64:
                                        try:
                                            img_bytes = base64.b64decode(sub.imagem_base64)
                                            st.image(img_bytes, caption=f"Anexo", use_column_width=True)
                                        except Exception:
                                            pass

                            with st.expander("Adicionar Subtarefa", expanded=False):
                                with st.form(key=f"form_sub_{t.id}", clear_on_submit=True):
                                    st_tit = st.text_input("Título", key=f"tit_sub_{t.id}")
                                    cs_1, cs_2 = st.columns(2)
                                    st_pz = cs_1.date_input("Prazo", value=date.today(), key=f"pz_sub_{t.id}")
                                    st_resp = cs_2.selectbox("Responsável", list(dict_usuarios.keys()), key=f"resp_sub_{t.id}")
                                    st_img = st.file_uploader("Anexo (Opcional)", type=["png", "jpg", "jpeg"], key=f"img_sub_{t.id}")

                                    if st.form_submit_button("Criar Subtarefa") and st_tit:
                                        img_sub_b64 = None
                                        if st_img is not None:
                                            img_sub_b64 = base64.b64encode(st_img.read()).decode("utf-8")

                                        id_resp_sub = dict_usuarios[st_resp]
                                        nova_sub = SubTarefa(
                                            titulo=st_tit, 
                                            prazo=st_pz, 
                                            responsavel_id=id_resp_sub,
                                            imagem_base64=img_sub_b64,
                                            tarefa_id=t.id
                                        )
                                        db.add(nova_sub)
                                        
                                        if id_resp_sub != user_id:
                                            notif_sub = Notificacao(mensagem=f"Subtarefa atribuída por {st.session_state.username}: '{st_tit}'", usuario_id=id_resp_sub)
                                            db.add(notif_sub)
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
                # Expander com o título: recolhido por padrão
                with st.expander(f"📄 {nota.titulo}", expanded=False):
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
