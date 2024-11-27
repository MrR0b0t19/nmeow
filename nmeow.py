##Script for dummies 
#
#by:fan_tasma
## 
import nmap
from openai import OpenAI
from dotenv import load_dotenv
from tqdm import tqdm
from rich.console import Console
from rich.table import Table

def hosts_scan(network, arguments):
    """
    Realizamos un escaneo rápido de los hosts para determinar cuáles están activos dentro de una red específica.
    
    Args:
        network (str): La dirección de la red o el rango de IP a escanear.
        arguments (str): Los argumentos de Nmap a utilizar para el escaneo.

    Returns:
        list: Lista de direcciones IP de hosts que están activos.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments=arguments)  # Escaneo con los argumentos proporcionados por el usuario
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]
    return active_hosts

def services_scan(network, arguments):
    """
    Escanea los servicios y versiones de los mismos en los hosts activos de una red.
    
    Args:
        network (str): La dirección de la red o el rango de IP a escanear.
        arguments (str): Los argumentos de Nmap a utilizar para el escaneo de servicios.

    Returns:
        dict: Diccionario que mapea cada host activo a los protocolos y servicios con sus respectivas versiones.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments=arguments)  # Escaneo con los argumentos proporcionados por el usuario
    network_d = {}
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            network_d[host] = {}
            for proto in nm[host].all_protocols():
                network_d[host][proto] = {}
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['product'] + " " + nm[host][proto][port]['version']
                    network_d[host][proto][port] = {'service': service, 'version': version}
    return network_d

def priorizar_hosts(network_d):
    """
    Agregará un modelo de IA (OpenAI) para pasarle los resultados y que nos diga qué más podemos hacer.

    Args:
        network_d (dict): Diccionario con los datos de los hosts y servicios escaneados.

    Returns:
        str: Respuesta generada por el modelo de IA con la priorización de los hosts y recomendaciones.
    """
    #para agregar tu api key crea un archivo nombralo ".env" y dentro de el crea la variable | OPENAI_API_KEY= 'api-aqui'| y pegas tu api, la libreria con ese nombre te ahorra la chamba
    load_dotenv() 
    client = OpenAI()
    chat_completion = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "Eres un experto en pentesting de tipo Red Team, encuentras, gestionas y priorizas vulnerabilidades para su cierre."},
            {"role": "user", "content": f"Teniendo en cuenta el siguiente descubrimiento de hosts, servicios y versiones, ordena los hosts de más vulnerable a menos vulnerable, explica que ataques se pueden realizar y propón los siguientes pasos para la fase de explotación de cada host. tambien recomienda herramientas, recuerda que ayudas a gente que no tiene mucho conocimiento en el area\n\n{network_d}"},
        ],
        model="gpt-3.5-turbo",  #esta parte de aqui es el modelo a seleccionar obvio tiene un costo pero su costo baja si ocupan el 3mini, solo que su respuesta no sera tan chida, ya saben el negocio :3
    )
    return chat_completion.choices[0].message.content

if __name__ == "__main__":
    console = Console()
    print("Bienvenido al escaner de red con un GPT.\n")
    
    # solicitamos rango o IP 
    network = input("\nPor favor, ingresa el rango de red o la IP a escanear (por ejemplo: 192.168.138.0/24): ")

    # solicitamos al usuario argumentos de Nmap
    arguments = input("Agrega los argumentos a utilizar en el escaneo de hosts (por ejemplo: -sn): ")

    #  escaneo de hosts
    print(f"\n\nEscaneando hosts en {network} con los argumentos: {arguments}")
    active_hosts = hosts_scan(network, arguments)

    #barra de hosts
    for _ in tqdm(active_hosts, desc="Escaneando hosts activos", unit="host"):
        pass  
    
    print(f"Hosts activos encontrados: {active_hosts}\n")
    
    # mostramos
    arguments_services = input("\nAgrega los argumentos a utilizar para el escaneo de servicios (por ejemplo: -sV): ")
    print(f"Escaneando servicios en {network} con los argumentos: {arguments_services}")
    network_d = services_scan(network, arguments_services)

    # barragood
    total_services = sum(len(network_d[host]) for host in network_d)
    for _ in tqdm(range(total_services), desc="Escaneando servicios", unit="servicio"):
        pass  
    
    print("\nEscaneo de servicios completado.")
    
    # Tabla con resultados xd
    table = Table(show_header=True, header_style="bold magenta", title="Servicios y versiones de Hosts Activos")
    table.add_column("Name/IP", justify="left", style="bold red")
    table.add_column("Servcio", justify="left", style="bold")
    table.add_column("Protocolo", justify="left", style="bold cyan")
    table.add_column("Versión", justify="left", style="bold yellow")
    #table.add_column("Recomendaciones", justify="left", style="bold yellow")

    for host, protocols in network_d.items():
        for proto, ports in protocols.items():
            for port, details in ports.items():
                table.add_row(
                    host,
                    details['service'],
                    proto,
                    details['version']
                )
    
    console.print(table)
    
    # Priorizamos hosts y obtenemos recomendaciones del GPT
    print("Generando recomendaciones...")
    recommendations = priorizar_hosts(network_d)
    
    # Mostrar las recomendaciones
    console.print("[bold green]Recomendaciones de la IA:[/bold green]")
    console.print(recommendations)
