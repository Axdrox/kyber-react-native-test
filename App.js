global.Buffer = require('buffer').Buffer;
import React, { useEffect, useState } from 'react';
import { StyleSheet, Text, View, Button, Alert, TextInput, ScrollView } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

import CryptoES from 'crypto-es';


const kyber = require('crystals-kyber');


//const hash = CryptoES.SHA3("Message");
//console.log(hash);

function generarClavesKyber() {
  // To generate a public and private key pair (pk, sk)
  let pk_sk = kyber.KeyGen512();
  let pk = pk_sk[0];
  let sk = pk_sk[1];

  // To generate a random 256 bit symmetric key (ss) and its encapsulation (c)
  let c_ss = kyber.Encrypt512(pk);
  let c = c_ss[0];
  let ss1 = c_ss[1];

  // To decapsulate and obtain the same symmetric key
  let ss2 = kyber.Decrypt512(c, sk);

  return { ss1, ss2 };
}

//Se puede ver la longitud del buffer, regresa el tamaño en bytes
//console.log(ss1.length);
//console.log(ss1);

//Comparación de tamaño de la clave con encode de hex o base64
/*
  const publicKeytoHex = Array.from(pk).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase()
  const sharedSecretToHex_1 = Array.from(ss1).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase()
  const sharedSecretToHex_2 = Array.from(ss2).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase()
  console.log(publicKeytoHex.length);
  console.log(Buffer.from(pk).toString('base64').length);
  console.log("Shared Secret 1: ", sharedSecretToHex_1);
  console.log("Shared Secret 2: ", sharedSecretToHex_2);
*/

//    COMPARAR ARREGLOS
function ArrayCompare(a, b) {
  // check array lengths
  if (a.length != b.length) {
    return 0;
  }
  // check contents
  for (let i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}
/*
  let result
  if (ArrayCompare(ss1, ss2))
    result = "Las claves simétricas son identicas, ¡¡¡ÉXITO!!! 😄"
  else
    result = "Las claves simétricas son diferentes, ¡FALLÓ! 😞"

  console.log(result);
*/

// Test function with KATs
//kyber.Test768();

/*
const encrypted = CryptoES.AES.encrypt("Message", sharedSecretToHex_1);
const decrypted = CryptoES.AES.decrypt(encrypted, sharedSecretToHex_2);
console.log("CIFRADO: " + encrypted);
console.log("DESCIFRADO: " + decrypted.toString(CryptoES.enc.Utf8));
console.log(encrypted.salt.toString())
*/

//const key = CryptoES.enc.Hex.parse(sharedSecretToHex_1);

// CIFRADO SIMÉTRICO
/*
  const iv = CryptoES.enc.Hex.parse('101112131415161718191a1b1c1d1e1f');

  const encrypted2 = CryptoES.AES.encrypt("Hola cómo estás, mi nombre es Alejandro", ss1, { iv: iv, mode: CryptoES.mode.CBC });
  console.log("TEXTO CIFRADO B64: "+encrypted2.ciphertext.toString(CryptoES.enc.Base64));

  const ciphertext = encrypted2.ciphertext.toString(CryptoES.enc.Base64);
  console.log("tipo: " + typeof (ciphertext));


  const words = CryptoES.enc.Base64.parse(ciphertext);
  const decrypted2 = CryptoES.AES.decrypt({ ciphertext: words }, ss2, { iv: iv });
  console.log("DESCIFRADO: " + decrypted2.toString(CryptoES.enc.Utf8));
*/


function cifrarAES(textoClaro, ss1) {
  //Crear nuestra string para ingresar a funcion hash que sera el IV
  let fecha = new Date;
  let entradaHash = fecha.getDate().toString() + fecha.getMonth() + fecha.getFullYear() + fecha.getHours();
  const iv = CryptoES.SHA3(entradaHash, { outputLength: 256 });
  //console.log(iv.toString());

  //Para dejarlo en objeto del tipo WordArray
  const key = CryptoES.lib.WordArray.create(ss1);

  // Para que ambos utilicen la misma sal y puedan descifrar con la kdf
  let fecha2 = new Date;
  let entradaHash2 = "P" + fecha2.getDate().toString() + "Q" + fecha2.getMonth() + fecha2.getFullYear() + "C" + fecha2.getHours();
  //const salt = CryptoES.SHA256(entradaHash2);
  const salt = CryptoES.SHA3(entradaHash2, { outputLength: 256 });
  //console.log(salt.toString());
  const key128Bits = CryptoES.PBKDF2(key, salt, { keySize: 128 / 32 });

  /*                                         KYBER KEY vs KDF FROM KYBER KEY
    PARA MEDIR TIEMPOS DE CIFRADO CON AES128 (UTILIZANDO UNA KDF) Y AES256 (UTILZIANDO LA CLAVE COMPARTIDA DE KYBER)
  
    //SI SE NECESITA REDUCIR EL TAMANIO
    const salt = CryptoES.lib.WordArray.random(128 / 8);
    //Generar una clave con KDF a partir de la clave compartida de kyber
    const key128Bits = CryptoES.PBKDF2(key, salt, { keySize: 128 / 32 });
  
    const startTime = performance.now();
    const ciferWithKyberKey = CryptoES.AES.encrypt(textoClaro, key, { iv: iv, mode: CryptoES.mode.CBC });
    const endTime = performance.now();
    const executionTime = endTime - startTime;
    console.log("Tiempo de ejecucion de microsegundos AES256: " + executionTime);
    //NOTE: SigBytes is a property of the WordArray class in the CryptoJS library. It represents the number of bytes in the WordArray object.
    console.log("EL NUMERO DE BYTES DE LA LLAVE KYBER QUE SE OCUPO PARA CIFRAR CON AES: " + ciferWithKyberKey.key.sigBytes.toString());
  
    const startTime2 = performance.now();
    const cipherWithKDF128Key = CryptoES.AES.encrypt(textoClaro, key128Bits, { iv: iv, mode: CryptoES.mode.CBC });
    const endTime2 = performance.now();
    const executionTime2 = endTime2 - startTime2;
    console.log("\nTiempo de ejecucion de microsegundos AES128: " + executionTime2);
    //NOTE: SigBytes is a property of the WordArray class in the CryptoJS library. It represents the number of bytes in the WordArray object.
    console.log("EL NUMERO DE BYTES DE LA LLAVE KDF QUE SE OCUPO PARA CIFRAR CON AES: " + cipherWithKDF128Key.key.sigBytes.toString());
  */

  return CryptoES.AES.encrypt(textoClaro, key128Bits, { iv: iv, mode: CryptoES.mode.CBC }).ciphertext.toString(CryptoES.enc.Base64);
}

function descifrarAES(textoCifrado, ss2) {
  // Convierte el texto cifrado de base 64 a un objeto WordArray
  const words = CryptoES.enc.Base64.parse(textoCifrado);

  //Crear nuestra string para ingresar a funcion hash que sera el IV
  let fecha = new Date;
  let entradaHash = fecha.getDate().toString() + fecha.getMonth() + fecha.getFullYear() + fecha.getHours();
  const iv = CryptoES.SHA3(entradaHash, { outputLength: 256 });

  //Para dejarlo en objeto del tipo WordArray
  const key = CryptoES.lib.WordArray.create(ss2);

  //SI SE NECESITA REDUCIR EL TAMANIO
  // Para que ambos utilicen la misma sal y puedan descifrar con la kdf
  let fecha2 = new Date;
  let entradaHash2 = "P" + fecha2.getDate().toString() + "Q" + fecha2.getMonth() + fecha2.getFullYear() + "C" + fecha2.getHours();
  const salt = CryptoES.SHA3(entradaHash2, { outputLength: 256 });
  const key128Bits = CryptoES.PBKDF2(key, salt, { keySize: 128 / 32 });

  return CryptoES.AES.decrypt({ ciphertext: words }, key128Bits, { iv: iv, mode: CryptoES.mode.CBC }).toString(CryptoES.enc.Utf8);
}


export default function App() {

  //Variables de estado
  /*
    const [clavePk, setPk] = useState();
    const [claveSk, setSk] = useState();
    const [claveEncapsulado, setEncapsulado] = useState();
    const [resultadoClaves, setResultadoClaves] = useState();
  */
  const [secretoCompartido_1, setSecretoCompartido_1] = useState();
  const [secretoCompartido_2, setSecretoCompartido_2] = useState();
  const [textoClaro, setTextoClaro] = useState();
  const [textoCifradoAES, setTextoCifradoAES] = useState();
  const [textoDescifradoAES, setTextoDescifradoAES] = useState();

  /*
    const clavePk_base64 = Buffer.from(pk).toString('base64');
    const claveSk_base64 = Buffer.from(sk).toString('base64');
    const encapsulado_base64 = Buffer.from(c).toString('base64');
  */

  /*
    AGREGAR EN FUNCIÓN ONPRESS DE BOTÓN

        <Text>Clave pública Kyber:{"\n"}{clavePk}{"\n"}{"\n"}</Text>

        <Text>Clave privada Kyber:{"\n"}{claveSk}{"\n"}{"\n"}</Text>

        <Text>Encapsulado de clave:{"\n"}{claveEncapsulado}{"\n"}{"\n"}</Text>
  */
  let claveSimetricas;
  return (
    <SafeAreaProvider style={styles.container}>
      <SafeAreaView>
        <ScrollView>
          <Text> CRYSTALS-KYBER TEST </Text>

          <Button
            title="Generar claves de Kyber"
            onPress={() => {
              //Para observar las claves públicas y privadas de Kyber, así como el encapsulado
              /*
              setPk(clavePk_base64),
                setSk(claveSk_base64),
                setEncapsulado(encapsulado_base64),
                */

              //let { ss1, ss2 } = generarClavesKyber();

              this.claveSimetricas = generarClavesKyber();
              let ss1 = this.claveSimetricas.ss1,
                ss2 = this.claveSimetricas.ss2;

              const secretoCompartido_1_base64 = Buffer.from(ss1).toString('base64');
              const secretoCompartido_2_base64 = Buffer.from(ss2).toString('base64');
              setSecretoCompartido_1(secretoCompartido_1_base64);
              setSecretoCompartido_2(secretoCompartido_2_base64);

              //setResultadoClaves(ArrayCompare(secretoCompartido_1, secretoCompartido_2)?"Claves simétricas iguales. ✅":"Claves simétricas no coinciden.");
              //<Text>Resultado: {"\n"}{resultadoClaves}{"\n"}{"\n"}</Text>

              setTextoCifradoAES("");
              setTextoDescifradoAES("");
            }}
          />

          <Text>Secreto compartido 1:{"\n"}{secretoCompartido_1}{"\n"}</Text>
          <Text>Secreto compartido 2:{"\n"}{secretoCompartido_2}{"\n"}</Text>

          <TextInput style={styles.textInput} placeholder='Escribe algo'
            onChangeText={(textoClaro) => {
              setTextoClaro(textoClaro),
                setTextoCifradoAES(""),
                setTextoDescifradoAES("")
            }}>
          </TextInput>

          <Button
            title="Cifrar con AES"
            onPress={() => {
              let ss1 = this.claveSimetricas.ss1;
              //const startTime = performance.now();
              setTextoCifradoAES(cifrarAES(textoClaro, ss1));
              //const endTime = performance.now();

              //const executionTime = endTime - startTime;
              //console.log('Execution time:', executionTime, 'milliseconds');

              //Limpiar
              setTextoDescifradoAES("");
            }}
          />
          <Text>{textoCifradoAES}</Text>

          <Button
            title="Descifrar con AES"
            onPress={() => {
              let ss2 = this.claveSimetricas.ss2;
              try {
                setTextoDescifradoAES(descifrarAES(textoCifradoAES, ss2));
              }
              catch (e) {

              }
            }}
          />
          <Text>{textoDescifradoAES}</Text>

        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  textInput: {
    borderWidth: 1,
    borderRadius: 10,
    padding: 10,
    margin: 10

  }
});