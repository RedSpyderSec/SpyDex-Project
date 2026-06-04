# SpyDex v0.1.8 🕸️
*El Proxy Interceptor Interactivo de Seguridad en la Terminal (TUI)*

SpyDex es un proxy de seguridad interactivo estilo "Burp Suite" diseñado para ejecutarse completamente desde la CLI. Permite interceptar peticiones, modificar tráfico sobre la marcha, repetir consultas (Repeater), codificar/decodificar información y realizar escaneos pasivos y activos de seguridad en tus aplicaciones web.

---

## 📋 Requisitos Previos

Para compilar y ejecutar SpyDex, necesitas tener instalado:
* **Go** (versión 1.20 o superior). Puedes verificar tu versión con:
  ```bash
  go version
  ```
* Un emulador de terminal compatible con secuencias ANSI de color y codificación UTF-8 (la mayoría de las terminales modernas en Linux y macOS).

---

## 🛠️ Compilación

1. Entra al directorio del proyecto:
   ```bash
   cd /ruta/a/SpyDex
   ```

2. Descarga y sincroniza las dependencias necesarias:
   ```bash
   go mod tidy
   ```

3. Compila el ejecutable del proyecto:
   ```bash
   go build -o spydex ./cmd/spydex/main.go
   ```

Esto generará un archivo ejecutable llamado `spydex` en el directorio actual.

---

## 🚀 Instalación y Ejecución

### Ejecución Directa
Puedes iniciar el proxy directamente especificando la dirección y puertos opcionales:
```bash
./spydex -addr ":8080"
```

### Parámetros de Ejecución (Flags)
* `-addr`: Dirección y puerto de escucha para el proxy (por defecto `:8080`).
* `-db`: Ruta personalizada de la base de datos SQLite (por defecto se creará en `~/.local/share/spydex/history.db`).
* `-ca-cert`: Fichero del certificado raíz CA de interceptación (por defecto `ca.pem`).
* `-ca-key`: Fichero de la clave del certificado raíz CA (por defecto `ca.key`).

### Instalación en el Sistema
Si deseas instalar `spydex` de forma global para ejecutarlo desde cualquier directorio:
```bash
go install ./cmd/spydex
```
*(Asegúrate de que tu directorio `$GOPATH/bin` o `~/go/bin` esté agregado a tu variable de entorno `$PATH`).*

---

## 🔒 Configuración de Interceptación HTTPS (Certificado CA)

Para poder descifrar e interceptar tráfico HTTPS sin advertencias de certificados inválidos en el navegador:

1. **Generar la CA:** Ejecuta `spydex` al menos una vez. El programa generará de forma automática los archivos `ca.pem` y `ca.key` en el directorio donde lo lances.
2. **Importar Certificado:** Abre tu navegador favorito e importa el archivo `ca.pem` generado:
   * **Firefox:** *Ajustes -> Privacidad y seguridad -> Certificados -> Ver certificados -> Importar...* Selecciona `ca.pem` y marca la casilla *"Confiar en esta CA para identificar sitios web"*.
   * **Chrome/Chromium:** *Configuración -> Privacidad y seguridad -> Seguridad -> Gestionar certificados -> Autoridades -> Importar...*
3. **Configurar el Proxy:** Apunta el proxy de tu sistema o de tu navegador a `127.0.0.1:8080`. (Recomendamos usar extensiones como *FoxyProxy* en Firefox para activar y desactivar el proxy con un solo clic).

---

## ⌨️ Atajos Básicos de Navegación

* `1` - `5`: Cambiar de pestaña (Intercept, History, Repeater, Decoder, Automator).
* `Tab`: Cambiar el foco entre paneles activos.
* `Flechas` o `k/j`: Desplazamiento de listas o scrolls de texto.
* `e` / `Enter`: Entrar en **Modo Edición** (para alterar peticiones en Intercept, Repeater o escribir en el Decoder).
* `Esc`: Salir del Modo Edición para regresar al **Modo Comando** de la interfaz.
* `Ctrl+C`: Menú de apagado y confirmación para salvar la base de datos.
# SpyDex-Project
