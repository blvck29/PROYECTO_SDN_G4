# PROYECTO_SDN_G4

## Descripción

Este proyecto tiene como objetivo implementar una solución basada en **Redes Definidas por Software (SDN)** para gestionar y asegurar el acceso a la red de una institución educativa. A través de un controlador **Floodlight**, se implementan módulos que permiten controlar el acceso de usuarios, restringir el acceso a recursos privilegiados y monitorizar el estado de la red en tiempo real.

### Objetivos principales del proyecto:

1. **Control de acceso a la red según rol**: Implementación de un módulo que valida las credenciales de los usuarios y asigna reglas en la red en función de su rol (alumno, docente, administrativo, etc.).
2. **Restricción de acceso a recursos privilegiados**: Un módulo que limita el acceso a servicios y recursos críticos (servidores de notas, bases de datos) según el rol del usuario.
3. **Monitorización centralizada**: Uso de **Prometheus** y **Grafana** para recolectar métricas de los nodos y switches de la red, mostrando estas métricas en dashboards interactivos y generando alertas automáticas cuando se superan ciertos umbrales.

## Miembros del equipo

- **Daniel Carry**
- **David Carry**
- **Yisus**
- **Fabricio Karry**
- **Nilo**

## Tecnologías utilizadas

- **Floodlight**: Controlador SDN para gestionar las reglas de red.
- **Open vSwitch (OvS)**: Switch virtual compatible con OpenFlow.
- **FreeRADIUS + OpenLDAP**: Para autenticar a los usuarios y asignarles un rol específico según sus credenciales.
- **MySQL**: Base de datos para almacenar usuarios, roles y reglas de acceso.
- **Suricata IDS**: Sistema de detección de intrusos.
- **Prometheus**: Sistema de monitoreo para recopilar métricas de la red.
- **Grafana**: Herramienta de visualización para crear dashboards con métricas de Prometheus.
- **Python**: Lenguaje utilizado para implementar scripts y la lógica de comunicación entre los módulos.

## Módulos Implementados

### 1. **Módulo de Control de Acceso por Rol**

Este módulo valida las credenciales de los usuarios y asigna reglas en la red basadas en su rol (alumno, docente, administrativo). Utiliza **FreeRADIUS** para la autenticación y **Floodlight** para gestionar las reglas OpenFlow.

### 2. **Módulo de Restricción de Acceso a Recursos Privilegiados**

Este módulo restringe el acceso a recursos críticos, como servidores de notas y bases de datos, según el rol del usuario. Solo los usuarios autorizados pueden acceder a estos recursos, gracias a las reglas definidas por **Floodlight**.

### 3. **Módulo de Monitorización Centralizada**

Utiliza **Prometheus** y **Grafana** para recopilar métricas de los nodos y switches de la red. El módulo permite visualizar el rendimiento de la red en tiempo real, generar alertas automáticas ante caídas de rendimiento, y crear dashboards interactivos.

## Instrucciones para ejecutar el proyecto

### 1. **Instalación de dependencias**

Antes de ejecutar el proyecto, asegúrate de tener instaladas las siguientes dependencias:

- **Floodlight**: Descargado y configurado en tu máquina.
- **Open vSwitch (OvS)**: Instalado y funcionando.
- **Prometheus**: Configurado para recopilar métricas de los nodos.
- **Grafana**: Instalado y conectado a Prometheus.
- **Suricata**: Instalado en el gateway para monitoreo de tráfico.
- **FreeRADIUS**: Configurado para la autenticación de usuarios.

### 2. **Ejecutar los scripts**

Para ejecutar los scripts de cada módulo, sigue estos pasos:

1. **Control de acceso por rol**: Corre el script para verificar que las credenciales se validen y las reglas de acceso se asignen correctamente.
2. **Restricción de acceso a recursos privilegiados**: Ejecuta el script para verificar que los recursos críticos se bloqueen o permitan según el rol.
3. **Monitorización centralizada**: Asegúrate de que **Prometheus** esté recopilando las métricas y que **Grafana** esté mostrando los dashboards.

### 3. **Ejemplo de ejecución**

```bash
python control_acceso.py
python restriccion_recursos.py
python monitorizacion.py
