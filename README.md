## 💬 Chat Empresarial: Solución de Comunicación Segura

Chat Empresarial es una plataforma de comunicación interna diseñada para ambientes de trabajo. Utiliza Python (Flask) para el backend y Socket.IO para ofrecer mensajería en tiempo real, autenticación segura con Flask-Login, y soporte para múltiples salas de chat persistentes a través de MySQL.

## 🎯 Características Principales

Autenticación Segura: Registro e inicio de sesión de usuarios gestionado por Flask-Login y contraseñas hasheadas (generate_password_hash) para máxima seguridad.

Mensajería en Tiempo Real: Comunicación instantánea habilitada por Socket.IO.

Salas de Chat Persistentes: Las salas de chat se almacenan en una base de datos MySQL, permitiendo que la lista de salas persista incluso si el servidor se reinicia.

Gestión de Salas: Los usuarios autenticados pueden crear y unirse a salas. El creador de una sala tiene la capacidad de eliminarla.

Mensajería Privada (P2P): Soporte para el envío de mensajes directos entre usuarios en línea.

Transferencia de Archivos: Permite a los usuarios subir archivos a través de una ruta HTTP protegida y notificar a la sala correspondiente.

## 🛠️ Stack Tecnológico

Esta es la lista de las principales tecnologías utilizadas en el desarrollo de la aplicación:

| Componente | Tecnología | Rol |
| :--- | :--- | :--- |
|Backend / Web Server| Python (Flask) | Manejo de rutas HTTP (login, registro, subida de archivos) |
|Comunicación en Tiempo Real| Flask-SocketIO | Gestión de conexiones persistentes (WebSockets) para el chat |
|Base de Datos| MySQL | Almacenamiento de usuarios (usuarios), salas (salas) y sus creadores |
|Seguridad de Sesión| Flask-Login / Werkzeug | Manejo de sesiones, autenticación de usuarios y hashing de contraseñas |
|Rutas/APIs| CORS | Configuración para permitir conexiones desde diferentes orígenes (si el frontend está separado)|



## ⚙️ Configuración y Despliegue

Sigue estos pasos para poner el servidor en funcionamiento.

## 1. Requisitos Previos

Python 3.9+

MySQL Server (Configurado y ejecutándose)

## 2. Configuración del Entorno

Clona el repositorio:

git clone [URL_DEL_REPOSITORIO]
cd chat_empresarial


Crea un entorno virtual e instálalo:

python -m venv venv
source venv/bin/activate   # En Linux/macOS
.\venv\Scripts\activate    # En Windows


Instala las dependencias de Python:

pip install flask flask-socketio flask-cors mysql-connector-python flask-login werkzeug


## 3. Configuración de la Base de Datos (MySQL)

El servidor asume la existencia de la base de datos y creará las tablas necesarias si no existen al iniciar.

Asegúrate de que tu servidor MySQL esté corriendo.

Accede a tu interfaz de MySQL (Workbench, consola) y crea la base de datos si no existe:

CREATE DATABASE chat_empresa;


Modifica las credenciales: Abre el archivo principal de la aplicación (tu_archivo_principal.py) y modifica las siguientes variables para que coincidan con tu configuración de MySQL:

DB_HOST = 'localhost'

DB_USER = 'root'

DB_PASSWORD = 'Tu_Contraseña' # ¡CAMBIA ESTA CONTRASEÑA!

DB_NAME = 'chat_empresa'


## 4. Estructura de la Base de Datos

El script de Python se encarga de crear automáticamente estas tablas si no existen:

Tabla usuarios
| Columna| Tipo de Dato | Descripción |
| :--- | :--- | :--- |
|id| INT (PK, AUTO_INCREMENT) | ID único del usuario. |
|username| VARCHAR(50) (UNIQUE) | Nombre de usuario. |
|password_hash| VARCHAR(255) | Contraseña hasheada y salada con Werkzeug. |

Tabla salas
| Columna| Tipo de Dato | Descripción |
| :--- | :--- | :--- |
|nombre| VARCHAR(50) (PK) | Nombre único de la sala de chat. |
|creador_usuario| VARCHAR(50) | Nombre del usuario que creó la sala. |

## 5. Ejecución del Servidor

Ejecuta el servidor principal de Flask-SocketIO:

python tu_archivo_principal.py 


El servidor estará disponible en http://0.0.0.0:5000.

## 6. Estructura de Archivos (Asumida)

El código asume una estructura de directorios que separa el frontend y el backend (ejemplo):

|Archivo/Directorio| Propósito | 
| :--- | :--- |
| tu_archivo_principal.py | Contiene el código de Flask, SocketIO y la lógica del backend. |
| uploads | Carpeta para almacenar los archivos subidos por los usuarios. |
| templates | Contiene los archivos HTML (índice, login, registro) renderizados por Flask |
| frontend | Contiene archivos estáticos (CSS, JavaScript del cliente) que manejan la interfaz. |

## 🔒 Notas de Seguridad

Clave Secreta: Asegúrate de cambiar app.config['SECRET_KEY'] por una cadena de caracteres única y compleja en producción.

Contraseñas: El uso de generate_password_hash garantiza que las contraseñas nunca se almacenen en texto plano.

Archivos Subidos: La función secure_filename ayuda a prevenir vulnerabilidades de recorrido de ruta (path traversal) al guardar archivos subidos.
