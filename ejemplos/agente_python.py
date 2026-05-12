class AgenteSeguridad:

    def __init__(self, grafo):

        self.g = grafo
        self.ns = "http://www.miOntologia.org/ciberseguridad#"


    def recomendar(self, amenaza):

        query = f"""
        PREFIX ciber: <{self.ns}>

        SELECT ?control
        WHERE {{
            ?control ciber:mitiga ciber:{amenaza} .
        }}
        """

        resultados = list(self.g.query(query))

        if resultados:

            return [
                str(row.control).split("#")[-1]
                for row in resultados
            ]

        else:

            return []


    def evaluar_riesgo(self, amenaza):

        controles = self.recomendar(amenaza)

        cantidad = len(controles)

        if cantidad >= 2:

            return "RIESGO BAJO — múltiples controles disponibles"

        elif cantidad == 1:

            return "RIESGO MEDIO — un control disponible"

        else:

            return "RIESGO ALTO — sin controles definidos"



# Ejecutar agente
agente = AgenteSeguridad(g)

print("\n=== RECOMENDACIONES DEL AGENTE ===\n")

amenazas = [
    "Phishing_Corporativo",
    "Malware_Ransomware",
    "DDoS_HTTP_Flood"
]

for amenaza in amenazas:

    controles = agente.recomendar(amenaza)

    print(f"Amenaza detectada: {amenaza}")

    if controles:
        print(f"Controles recomendados: {controles}")
    else:
        print("Controles recomendados: No encontrados")

    print(f"Evaluación: {agente.evaluar_riesgo(amenaza)}")

    print("-" * 50)
