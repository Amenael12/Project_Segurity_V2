const axios = require('axios');
const fs = require('fs'); // Importar el módulo fs de Node.js

const consumirAPI = async () => {
  try {
    const url = 'http://127.0.0.1:8000/api/scan/';
    const datos = {
      project_path: 'C:/Users/herre/OneDrive/Escritorio/Proyescto_Diseño',
      language: 'JavaScript'
    };

    const respuesta = await axios.post(url, datos, {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (respuesta.status === 200) {
      const reportContent = respuesta.data.report_content;
      console.log('Contenido del reporte:', reportContent);

      // Guardar el reporte en un archivo (opcional)
      fs.writeFileSync('reporte.txt', reportContent);
      console.log('El reporte se ha guardado en el archivo reporte.txt');
    } else {
      console.log(`Error: ${respuesta.status} - ${respuesta.statusText}`);
    }
  } catch (error) {
    console.error('Error:', error);
  }
};

console.log("Este es el proyecto: " + 'Proyescto_Diseño');
consumirAPI();