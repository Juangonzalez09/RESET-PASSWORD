from flask import Flask, render_template, request, flash, redirect, url_for
from ldap3 import Server, Connection, ALL, Tls ,MODIFY_REPLACE
from ldap3.core.exceptions import LDAPBindError
from dotenv import load_dotenv
import ssl,os

app = Flask(__name__)
tls_config = Tls(
    validate=ssl.CERT_NONE,  # O CERT_NONE si no quieres validar el certificado
    version=ssl.PROTOCOL_TLSv1_2,  # Ruta a tu archivo .crt
)

load_dotenv()  # Carga las variables del archivo .env

@app.route('/')
def cambiar_contrasena():
        admin_user = os.getenv('LDAP_ADMIN_USER')
        admin_pass = os.getenv('LDAP_ADMIN_PASS')
        servidor_ldap = os.getenv('LDAP_SERVER')
        base_dn = os.getenv('LDAP_BASE_DN')

        try:
            # Conectar al servidor con cuenta admin
            server = Server(servidor_ldap, port=636, use_ssl=True, get_info=ALL, tls=tls_config)
            conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)

            # Buscar el usuario por nombre de cuenta
            conn.search(search_base=base_dn,
                        search_filter=f'(sAMAccountName={"jader"})',
                        attributes=['distinguishedName'])

            if conn.entries:
                usuario_dn = conn.entries[0].distinguishedName.value

                # Cambiar la contraseña
                nueva_contra = '"Ingreso2050**"'.encode('utf-16-le')
                conn.modify(usuario_dn, {'unicodePwd': [(MODIFY_REPLACE, [nueva_contra])]})

                conn.unbind()
                return ('Contraseña cambiada exitosamente', 'success')
            else:
                conn.unbind()
                return('Usuario no encontrado', 'danger')

        except LDAPBindError:
            return('No se pudo conectar al servidor LDAP. Verifica las credenciales.', 'danger')
        except Exception as e:
            return(f'Error inesperado: {str(e)}', 'danger')


if __name__ == '__main__':
    app.run(debug=True)
