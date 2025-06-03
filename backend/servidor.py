import os
import mysql.connector
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_cors import CORS
import logging
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Importar Flask-Login
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Configuración de la aplicación Flask y SocketIO
# Asegurarse de que Flask sepa dónde buscar los templates y archivos estáticos
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'frontend') # '..' para subir un nivel y luego ir a 'frontend'
)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

logging.basicConfig(level=logging.INFO)

# ¡IMPORTANTE! Cambia esto a una cadena de caracteres compleja y secreta en producción.
# Esta clave es usada por Flask para firmar las cookies de sesión.
app.config['SECRET_KEY'] = 'tu_clave_secreta_super_segura_aqui_cambiala_siempre_!!!'

# Configuración de la base de datos MySQL
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = 'Abril2025'
DB_NAME = 'chat_empresa'

# Configuración de la carpeta para subir archivos
UPLOAD_FOLDER = 'uploads'
# Crea la carpeta 'uploads' si no existe
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Estructuras de datos en memoria para el estado del chat
salas = {}  # {'nombre_sala': [sid1, sid2, ...]}
usuarios_en_sala = {} # {sid: 'nombre_sala'}
usuarios_info = {} # {sid: 'nombre_usuario'} - Mantiene la asociación SID <-> nombre_usuario
usuarios_conectados_global = {} # {sid: {'usuario': 'nombre_usuario'}} - Lista de usuarios conectados globalmente
nombres_de_salas = set() # Conjunto de nombres de salas existentes, incluyendo las de la DB


# --- Configuración de Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # La vista a la que redirigir si se requiere login

# Clase de Usuario para Flask-Login
# Debe heredar de UserMixin para que Flask-Login funcione correctamente
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    # Flask-Login necesita este método para obtener el ID único del usuario
    def get_id(self):
        return str(self.id)

    # Puedes añadir un método para representar el objeto (útil para depuración)
    def __repr__(self):
        return f'<User {self.username}>'

# user_loader: Función que Flask-Login usa para recargar el objeto User desde el ID de sesión
@login_manager.user_loader
def load_user(user_id):
    mydb = get_db_connection()
    if mydb:
        # Usar dictionary=True para obtener los resultados como diccionarios (más fácil de acceder)
        mycursor = mydb.cursor(dictionary=True)
        try:
            mycursor.execute("SELECT id, username FROM usuarios WHERE id = %s", (user_id,))
            user_data = mycursor.fetchone()
            if user_data:
                return User(user_data['id'], user_data['username'])
            return None # Si el usuario no se encuentra
        except mysql.connector.Error as err:
            print(f"Error al cargar usuario de la base de datos: {err}")
            return None
        finally:
            mycursor.close()
            mydb.close()
    return None # Si no se puede conectar a la base de datos


# --- Funciones de Utilidad ---

def get_db_connection():
    """Establece una conexión a la base de datos MySQL."""
    try:
        mydb = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return mydb
    except mysql.connector.Error as err:
        print(f"Error al conectar a la base de datos: {err}")
        return None

def get_usuarios_en_sala(sala):
    """Obtiene los nombres de usuario de los usuarios actualmente en una sala específica."""
    sids_en_sala = salas.get(sala, [])
    # Filtra para asegurar que solo se devuelvan nombres válidos
    return [usuarios_info.get(sid) for sid in sids_en_sala if usuarios_info.get(sid)]

def cargar_salas_desde_db():
    """
    Carga las salas desde la base de datos y las emite a todos los clientes conectados.
    También actualiza el conjunto 'nombres_de_salas' en memoria.
    """
    mydb = get_db_connection()
    if mydb:
        mycursor = mydb.cursor()
        try:
            mycursor.execute("SELECT nombre, creador_usuario FROM salas")
            resultados = mycursor.fetchall()
            nombres_de_salas.clear() # Limpiar el conjunto actual antes de recargar
            salas_info_para_cliente = []
            for resultado in resultados:
                nombres_de_salas.add(resultado[0]) # Añadir solo el nombre al conjunto
                salas_info_para_cliente.append({'nombre': resultado[0], 'creador': resultado[1]})
            # Emitir a todos los clientes la lista actualizada de salas
            # Usamos to=None para broadcast (equivalente a broadcast=True en versiones anteriores)
            socketio.emit('actualizar_lista_salas', {'salas': salas_info_para_cliente}, to=None)
        except mysql.connector.Error as err:
            print(f"Error al cargar las salas desde la base de datos: {err}")
        finally:
            mycursor.close()
            mydb.close()


# --- Rutas HTTP (Flask) ---

# Ruta para el registro de nuevos usuarios
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    # Si el usuario ya está autenticado, redirigirlo al chat para evitar que se registre de nuevo
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Por favor, ingresa un nombre de usuario y contraseña.', 'error')
            return render_template('registro.html')

        mydb = get_db_connection()
        if mydb:
            mycursor = mydb.cursor()
            try:
                # Verificar si el nombre de usuario ya existe en la base de datos
                mycursor.execute("SELECT id FROM usuarios WHERE username = %s", (username,))
                if mycursor.fetchone():
                    flash('El nombre de usuario ya existe. Por favor, elige otro.', 'error')
                    return render_template('registro.html')

                # Hashear la contraseña antes de guardarla en la base de datos
                # generate_password_hash() se encarga de salting y hashing de forma segura
                hashed_password = generate_password_hash(password)

                sql = "INSERT INTO usuarios (username, password_hash) VALUES (%s, %s)"
                val = (username, hashed_password)
                mycursor.execute(sql, val)
                mydb.commit() # Confirmar la transacción en la base de datos
                flash('Registro exitoso. ¡Ahora puedes iniciar sesión!', 'success')
                return redirect(url_for('login')) # Redirigir a la página de login
            except mysql.connector.Error as err:
                print(f"Error al registrar usuario: {err}")
                flash(f'Error al registrar usuario: {err}', 'error')
                return render_template('registro.html')
            finally:
                mycursor.close()
                mydb.close()
        else:
            flash('Error de conexión a la base de datos.', 'error')
            return render_template('registro.html')
    return render_template('registro.html') # Renderiza el formulario de registro para peticiones GET

# Ruta para el inicio de sesión de usuarios
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si el usuario ya está autenticado, redirigirlo al chat
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        mydb = get_db_connection()
        if mydb:
            mycursor = mydb.cursor(dictionary=True) # Usar dictionary=True para acceder a los campos por nombre
            try:
                mycursor.execute("SELECT id, username, password_hash FROM usuarios WHERE username = %s", (username,))
                user_data = mycursor.fetchone()
                if user_data:
                    # Verificar la contraseña ingresada con la contraseña hasheada almacenada
                    if check_password_hash(user_data['password_hash'], password):
                        user = User(user_data['id'], user_data['username'])
                        login_user(user) # Inicia la sesión del usuario con Flask-Login
                        flash('¡Inicio de sesión exitoso!', 'success')
                        return redirect(url_for('chat')) # Redirigir a la página del chat
                    else:
                        flash('Contraseña incorrecta.', 'error')
                else:
                    flash('Nombre de usuario no encontrado.', 'error')
            except mysql.connector.Error as err:
                print(f"Error al intentar iniciar sesión: {err}")
                flash(f'Error al iniciar sesión: {err}', 'error')
            finally:
                mycursor.close()
                mydb.close()
        else:
            flash('Error de conexión a la base de datos.', 'error')
    return render_template('login.html') # Renderiza el formulario de login para peticiones GET

# Ruta para cerrar sesión
@app.route('/logout')
@login_required # Solo un usuario logueado puede acceder a esta ruta
def logout():
    logout_user() # Cierra la sesión del usuario actual
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login')) # Redirige a la página de login

# Ruta principal del chat, ahora protegida por login_required
@app.route('/')
@app.route('/chat') # Puedes acceder al chat vía / o /chat
@login_required # Asegura que solo usuarios logueados puedan acceder a la interfaz del chat
def chat():
    # El nombre de usuario del usuario autenticado está disponible a través de current_user.username
    return render_template('index.html', username=current_user.username)

# Ruta para subir archivos, también protegida
@app.route('/subir_archivo', methods=['POST'])
@login_required # Solo usuarios logueados pueden subir archivos
def subir_archivo():
    """Maneja la subida de archivos."""
    if 'archivo' not in request.files:
        return jsonify({'error': 'No se envió ningún archivo'}), 400

    archivo = request.files['archivo']

    if archivo.filename == '':
        return jsonify({'error': 'El archivo no tiene nombre'}), 400

    if archivo:
        try:
            # secure_filename() limpia el nombre del archivo para evitar ataques de path traversal
            filename = secure_filename(archivo.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            archivo.save(filepath)

            # El nombre de usuario se toma directamente del usuario autenticado (más seguro)
            usuario = current_user.username
            # La sala aún se toma del formulario, ya que el archivo se sube en el contexto de una sala
            sala = request.form.get('sala', 'general')

            # Emitir evento a la sala correspondiente para notificar sobre el archivo
            socketio.emit('archivo_recibido', {
                'usuario': usuario,
                'nombre_archivo': filename,
                'ruta': f'/{app.config["UPLOAD_FOLDER"]}/{filename}', # Ruta accesible desde el navegador
                'sala': sala,
                'timestamp': int(round(datetime.now().timestamp() * 1000)) # Añadir timestamp
            }, room=sala) # Emitir solo a los clientes en esa sala

            return jsonify({'mensaje': 'Archivo subido con éxito', 'nombre_archivo': filename}), 200
        except Exception as e:
            print(f"Error al subir archivo: {e}")
            return jsonify({'error': f'Error interno del servidor al subir archivo: {e}'}), 500
    return jsonify({'error': 'Error desconocido al subir el archivo'}), 500

# Ruta para descargar archivos
@app.route('/uploads/<nombre_archivo>', methods=['GET'])
# No se requiere login_required aquí si quieres que los archivos sean accesibles públicamente una vez subidos.
# Si quieres restringir la descarga a usuarios logueados, añade @login_required.
def descargar_archivo(nombre_archivo):
    try:
        # send_from_directory sirve el archivo de forma segura desde la carpeta especificada
        return send_from_directory(app.config['UPLOAD_FOLDER'], nombre_archivo, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'Archivo no encontrado.'}), 404


# --- Eventos de SocketIO ---

@socketio.on('connect')
# El argumento 'auth' es opcional y puede ser pasado por Flask-SocketIO en algunas configuraciones.
# Lo incluimos para evitar TypeError si se pasa.
def handle_connect(auth=None):
    """
    Maneja la conexión de un nuevo cliente Socket.IO.
    Asocia el SID con el usuario autenticado si existe.
    """
    sid = request.sid
    print(f'Cliente conectado: {sid}')

    # Solo si hay un usuario autenticado con Flask-Login, lo asociamos al SID
    if current_user.is_authenticated:
        usuarios_info[sid] = current_user.username
        usuarios_conectados_global[sid] = {'usuario': current_user.username}
        print(f'Usuario {current_user.username} (ID: {current_user.id}) asociado a la sesión {sid}')
        # Emitir la lista de usuarios conectados a todos, incluido el nuevo
        socketio.emit('usuarios_conectados', [{'id': s, 'nombre': info['usuario']} for s, info in usuarios_conectados_global.items()], to=None)
        # Cargar y emitir las salas al cliente que acaba de conectar
        cargar_salas_desde_db() # Esto ya emite a todos, incluyendo el nuevo cliente
    else:
        print(f"Cliente {sid} conectado sin autenticación Flask-Login.")
        # Podrías emitir un mensaje al cliente para que se loguee, o limitar su funcionalidad.
        # Por ahora, simplemente no se le asigna un nombre de usuario en memoria.


@socketio.on('disconnect')
def handle_disconnect():
    """Maneja la desconexión de un cliente Socket.IO."""
    sid = request.sid
    # Obtener el nombre de usuario asociado al SID antes de eliminarlo
    nombre_usuario = usuarios_info.get(sid)
    sala_actual = usuarios_en_sala.get(sid)

    print(f'Cliente desconectado: {sid} ({nombre_usuario if nombre_usuario else "Desconocido"}) de la sala: {sala_actual if sala_actual else "ninguna"}')

    # Eliminar al usuario de la lista global de conectados
    if sid in usuarios_conectados_global:
        del usuarios_conectados_global[sid]
        # Emitir a todos los clientes la lista actualizada de usuarios conectados
        emit('usuarios_conectados', [{'id': id, 'nombre': info['usuario']} for id, info in usuarios_conectados_global.items()], to=None)

    # Si el usuario estaba en una sala, sacarlo y notificar
    if sid in usuarios_en_sala:
        sala = usuarios_en_sala[sid]
        leave_room(sala)
        if sid in salas.get(sala, []):
            salas[sala].remove(sid)
        del usuarios_en_sala[sid]
        emit('actualizar_usuarios', {'sala': sala, 'usuarios': get_usuarios_en_sala(sala)}, to=sala)
        emit('mensaje_sistema', {'texto': f'{nombre_usuario if nombre_usuario else "Un usuario"} ha abandonado la sala {sala}.'}, to=sala)

    # Eliminar la información del usuario de la memoria
    if sid in usuarios_info:
        del usuarios_info[sid]


@socketio.on('establecer_nombre_usuario')
# Esta función ahora es menos crítica ya que el nombre de usuario viene del login.
# Se mantiene para asegurar que el SID se asocie al nombre de usuario en memoria.
def handle_establecer_nombre_usuario(data):
    sid = request.sid
    # Solo procesamos si el usuario ya está autenticado con Flask-Login
    if current_user.is_authenticated:
        usuario_autenticado = current_user.username
        # Si el SID aún no tiene un nombre de usuario o es diferente al autenticado, lo actualizamos
        if usuarios_info.get(sid) != usuario_autenticado:
             usuarios_info[sid] = usuario_autenticado
             usuarios_conectados_global[sid] = {'usuario': usuario_autenticado}
             print(f'Usuario {usuario_autenticado} establecido/re-establecido para la sesión {sid} (desde login).')
             emit('usuarios_conectados', [{'id': id, 'nombre': info['usuario']} for id, info in usuarios_conectados_global.items()], to=None)
    else:
        # Si un cliente no autenticado intenta establecer un nombre, lo ignoramos o manejamos como error.
        print(f"Advertencia: Cliente {sid} intentó establecer usuario sin estar logueado: {data.get('usuario')}. Ignorado.")
        # Podrías emitir un error al cliente si quieres forzar el login.


@socketio.on('unirse_sala')
@login_required # La acción de unirse a una sala requiere que el usuario esté logueado
def handle_unirse_sala(data):
    sid = request.sid
    sala = data.get('sala')
    # El nombre de usuario se toma del usuario autenticado
    usuario = current_user.username
    sala_anterior = usuarios_en_sala.get(sid)

    # Si el usuario ya estaba en una sala y es diferente a la nueva, lo saca de la anterior
    if sala_anterior and sala_anterior != sala:
        leave_room(sala_anterior)
        if sid in salas.get(sala_anterior, []):
            salas[sala_anterior].remove(sid)
        emit('actualizar_usuarios', {'sala': sala_anterior, 'usuarios': get_usuarios_en_sala(sala_anterior)}, to=sala_anterior)
        emit('mensaje_sistema', {'texto': f'{usuario} ha abandonado la sala {sala_anterior}.'}, to=sala_anterior)
        usuarios_en_sala.pop(sid, None) # Elimina la entrada de la sala anterior

    # Unir al usuario a la nueva sala de SocketIO
    join_room(sala)
    usuarios_en_sala[sid] = sala # Asocia el SID con la sala actual
    if sala not in salas:
        salas[sala] = [] # Inicializa la lista de SIDs para la nueva sala si no existe
    if sid not in salas[sala]:
        salas[sala].append(sid) # Añade el SID a la lista de SIDs en la sala

    emit('actualizar_usuarios', {'sala': sala, 'usuarios': get_usuarios_en_sala(sala)}, to=sala) # Actualiza usuarios en la sala
    emit('mensaje_sistema', {'texto': f'{usuario} se ha unido a la sala {sala}.'}, to=sala) # Notifica a la sala
    emit('usuario_unido', {'usuario': usuario, 'sala': sala}, to=None) # Notifica a todos (broadcast)


@socketio.on('mensaje')
@login_required # La acción de enviar mensaje requiere que el usuario esté logueado
def handle_mensaje(data):
    """Maneja el envío de mensajes públicos y privados."""
    sid = request.sid
    texto = data.get('texto')
    destinatario = data.get('destinatario')
    # El nombre de usuario se toma del usuario autenticado
    usuario = current_user.username
    sala = usuarios_en_sala.get(sid)
    timestamp = int(round(datetime.now().timestamp() * 1000)) # Generar timestamp en el servidor

    if texto:
        if destinatario:
            destinatario_sid = None
            # Buscar el SID del destinatario por su nombre de usuario
            for s, u in usuarios_info.items():
                if u == destinatario:
                    destinatario_sid = s
                    break
            if destinatario_sid:
                # Emitir mensaje privado al destinatario
                emit('mensaje_privado', {'texto': texto, 'remitente': usuario, 'timestamp': timestamp}, to=destinatario_sid)
                # Emitir una copia del mensaje privado al remitente para que la vea en su propio chat
                emit('mensaje_privado', {'texto': f'Mensaje privado para {destinatario}: {texto}', 'remitente': usuario, 'timestamp': timestamp}, to=sid)
            else:
                emit('mensaje_sistema', {'texto': f'El usuario {destinatario} no está en línea o no existe.'}, to=sid)
        elif sala:
            # Emitir mensaje público a la sala
            emit('nuevo_mensaje', {'usuario': usuario, 'texto': texto, 'timestamp': timestamp}, to=sala)

@socketio.on('crear_sala')
@login_required # La acción de crear sala requiere que el usuario esté logueado
def handle_crear_sala(data):
    """Permite a un usuario crear una nueva sala."""
    sid = request.sid
    nombre_sala = data.get('nombre_sala')
    # El nombre de usuario se toma del usuario autenticado
    nombre_usuario = current_user.username

    if not nombre_sala:
        emit('sala_creada', {'error': 'El nombre de la sala no puede estar vacío.'}, to=sid)
        return

    nombre_sala = nombre_sala.strip()
    if not nombre_sala:
        emit('sala_creada', {'error': 'El nombre de la sala no puede ser solo espacios.'}, to=sid)
        return

    if len(nombre_sala) > 50:
        emit('sala_creada', {'error': 'El nombre de la sala es demasiado largo (máximo 50 caracteres).'}, to=sid)
        return

    mydb = get_db_connection()
    if mydb is None:
        emit('sala_creada', {'error': 'No se pudo conectar a la base de datos.'}, to=sid)
        return

    mycursor = mydb.cursor()
    try:
        # Verificar si la sala ya existe en la base de datos
        mycursor.execute("SELECT nombre FROM salas WHERE nombre = %s", (nombre_sala,))
        resultado = mycursor.fetchone()
        if resultado:
            emit('sala_creada', {'error': f'La sala "{nombre_sala}" ya existe.'}, to=sid)
            return

        sql = "INSERT INTO salas (nombre, creador_usuario) VALUES (%s, %s)"
        val = (nombre_sala, nombre_usuario)
        mycursor.execute(sql, val)
        mydb.commit() # Confirmar la creación de la sala en la DB
        print(f'Sala "{nombre_sala}" creada por {nombre_usuario} y guardada en la base de datos.')
        nombres_de_salas.add(nombre_sala) # Añadir el nuevo nombre al conjunto en memoria
        # Notificar a todos los clientes que se creó una nueva sala
        emit('sala_creada', {'nombre_sala': nombre_sala}, to=None)
        # Recargar la lista de salas para todos (esto también actualiza el frontend)
        cargar_salas_desde_db()

        # Unir al usuario a la nueva sala automáticamente
        # Primero, sacarlo de la sala actual si está en una y es diferente a la nueva
        sala_anterior = usuarios_en_sala.get(sid)
        if sala_anterior and sala_anterior != nombre_sala:
            leave_room(sala_anterior)
            if sid in salas.get(sala_anterior, []):
                salas[sala_anterior].remove(sid)
            emit('actualizar_usuarios', {'sala': sala_anterior, 'usuarios': get_usuarios_en_sala(sala_anterior)}, to=sala_anterior)
            emit('mensaje_sistema', {'texto': f'{nombre_usuario} ha abandonado la sala {sala_anterior}.'}, to=sala_anterior)
            usuarios_en_sala.pop(sid, None)

        join_room(nombre_sala) # Unir al usuario a la nueva sala
        usuarios_en_sala[sid] = nombre_sala
        if nombre_sala not in salas:
            salas[nombre_sala] = []
        if sid not in salas[nombre_sala]:
            salas[nombre_sala].append(sid)

        emit('mensaje_sistema', {
            'texto': f'Has creado y te has unido a la sala {nombre_sala}.'
        }, to=sid)

        emit('actualizar_usuarios', {
            'sala': nombre_sala,
            'usuarios': get_usuarios_en_sala(nombre_sala)
        }, to=nombre_sala)

    except mysql.connector.Error as err:
        print(f"Error al crear la sala en la base de datos: {err}")
        mydb.rollback() # Deshacer la transacción si hay un error
        emit('sala_creada', {'error': f'Error al crear la sala: {err}'}, to=sid)
    finally:
        if mydb and mydb.is_connected():
            mycursor.close()
            mydb.close()

@socketio.on('eliminar_sala')
@login_required # La acción de eliminar sala requiere que el usuario esté logueado
def handle_eliminar_sala(data):
    """Permite al creador de una sala eliminarla."""
    sid = request.sid
    nombre_sala = data.get('nombre_sala')
    # El nombre de usuario se toma del usuario autenticado
    usuario = current_user.username

    if not nombre_sala or not usuario:
        emit('mensaje_sistema', {'texto': 'Error al intentar eliminar la sala. Datos incompletos.'}, to=sid)
        return

    mydb = get_db_connection()
    if mydb:
        mycursor = mydb.cursor()
        try:
            # Verifica si el usuario actual es el creador de la sala en la DB
            mycursor.execute("SELECT creador_usuario FROM salas WHERE nombre = %s", (nombre_sala,))
            resultado = mycursor.fetchone()
            if resultado and resultado[0] == usuario: # Solo el creador puede eliminar la sala
                # Eliminar la sala de la base de datos
                mycursor.execute("DELETE FROM salas WHERE nombre = %s", (nombre_sala,))
                mydb.commit()

                # Actualizar la información en memoria
                if nombre_sala in nombres_de_salas:
                    nombres_de_salas.remove(nombre_sala)

                # Notificar a los usuarios en la sala que ha sido eliminada y hacerlos salir
                if nombre_sala in salas:
                    sids_en_sala_a_eliminar = list(salas[nombre_sala]) # Crear una copia para iterar de forma segura
                    for sid_usuario in sids_en_sala_a_eliminar:
                        if usuarios_en_sala.get(sid_usuario) == nombre_sala:
                            leave_room(nombre_sala, sid=sid_usuario) # Saca al usuario de la sala de SocketIO
                            del usuarios_en_sala[sid_usuario] # Elimina la entrada del usuario de qué sala está

                            # Notificar al cliente específico que su sala ha sido eliminada
                            emit('sala_eliminada_cliente', {'nombre_sala': nombre_sala}, to=sid_usuario)
                            emit('mensaje_sistema', {'texto': f'La sala "{nombre_sala}" ha sido eliminada. Has sido movido a la sala general.'}, to=sid_usuario)

                            # Mover al usuario a la sala 'general'
                            join_room('general', sid=sid_usuario)
                            usuarios_en_sala[sid_usuario] = 'general'
                            if 'general' not in salas:
                                salas['general'] = []
                            if sid_usuario not in salas['general']:
                                salas['general'].append(sid_usuario)
                            emit('actualizar_usuarios', {'sala': 'general', 'usuarios': get_usuarios_en_sala('general')}, to='general')
                            emit('mensaje_sistema', {'texto': f'{usuarios_info.get(sid_usuario, "Un usuario")} se ha unido a la sala general.'}, to='general')

                    del salas[nombre_sala] # Eliminar la sala del diccionario en memoria después de procesar a todos los usuarios
                else:
                    print(f"La sala {nombre_sala} no estaba en la memoria local 'salas', pero sí en DB. Consistencia arreglada.")

                # Notificar a todos los clientes que una sala fue eliminada
                emit('sala_eliminada', {'nombre_sala': nombre_sala}, to=None)
                # Volver a cargar la lista completa de salas para todos los clientes
                cargar_salas_desde_db()
                print(f'Sala "{nombre_sala}" eliminada por {usuario}.')
            else:
                emit('mensaje_sistema', {'texto': 'No tienes permiso para eliminar esta sala. Solo el creador puede hacerlo.'}, to=sid)
        except mysql.connector.Error as err:
            print(f"Error al eliminar la sala de la base de datos: {err}")
            mydb.rollback() # Deshacer la transacción si hay un error
            emit('mensaje_sistema', {'texto': f'Error al eliminar la sala: {err}'}, to=sid)
        finally:
            if mydb and mydb.is_connected():
                mycursor.close()
                mydb.close()
    else:
        emit('mensaje_sistema', {'texto': 'No se pudo conectar a la base de datos para eliminar la sala.'}, to=sid)

@socketio.on('solicitar_lista_salas')
@login_required # La acción de solicitar salas requiere que el usuario esté logueado
def handle_solicitar_lista_salas():
    """Un cliente solicita la lista actual de salas."""
    cargar_salas_desde_db()

# --- Ejecución del Servidor ---

if __name__ == '__main__':
    print("Iniciando servidor. Verificando/creando tablas de base de datos y salas iniciales...")
    mydb_init = get_db_connection()
    if mydb_init:
        cursor_init = mydb_init.cursor()
        try:
            # Crear tabla 'salas' si no existe
            cursor_init.execute("CREATE TABLE IF NOT EXISTS salas (nombre VARCHAR(50) PRIMARY KEY, creador_usuario VARCHAR(50))")
            # Crear tabla 'usuarios' si no existe
            cursor_init.execute("CREATE TABLE IF NOT EXISTS usuarios (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL)")

            # Insertar salas por defecto solo si no existen (INSERT IGNORE)
            salas_defecto = [('general', 'sistema'), ('desarrollo', 'sistema'), ('ventas', 'sistema')]
            for sala_nombre, creador in salas_defecto:
                cursor_init.execute("INSERT IGNORE INTO salas (nombre, creador_usuario) VALUES (%s, %s)", (sala_nombre, creador))
            mydb_init.commit() # Confirmar los cambios en la base de datos
            print("Tablas de salas y usuarios verificadas/creadas y salas por defecto aseguradas.")
        except mysql.connector.Error as err:
            print(f"Error al inicializar la base de datos para salas/usuarios: {err}")
        finally:
            cursor_init.close()
            mydb_init.close()

    # Iniciar el servidor Flask-SocketIO
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)