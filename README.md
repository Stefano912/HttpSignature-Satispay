# HttpSignature-Satispay
call sandbox satispay with http signature

IMPORT PROJECT

    Per importare il progetto su intellij IDEA bisogna preme su file -> Open -> selezionare la cartella Satispay

RUN

    Per esegui i test bisogna premere su run e lo script eseguirà in automatico tutti i test


PROJECT

    Ho deciso di inserire direttamente le chiavi nella classe con delle String statiche perché lo scopo dell'esercizio
    non è importare dei file ma firmare dei messaggi HTTP e chiamare il servizio https://staging.authservices.satispay.com/wally-services/protocol/tests/signature

    Ho implementato 6 test:
        - testMinHeader : esegue 4 testi con tutti i metodo HTTP (GET,PUT,POST,DELETE) inserendo il minimo numero di header, solamente
          (request-target)

        - testDeleteHeader : esegue il test con tutti gli header (request-target,date,digest) con il metodo delete

        - testGetHeader : esegue il test con tutti gli header (request-target,date,digest) con il metodo get

        - testPostHeader : esegue il test con tutti gli header (request-target,date,digest) con il metodo post

        - testPutHeader : esegue il test con tutti gli header (request-target,date,digest) con il metodo put

        - testHeaderCustom : esegue il test con degli header facilmente modificabili direttamente nel metodo del test,
          si possono aggiungere header inserendo la chiave ( quindi il nome) e il valore dell'header nella mappa che poi passo
          al metodo genericTest

TEST

    Vengono testate quattro condizioni:

        - "Assert.assertEquals(input,myResponse.get("signed_string"));" verifico se la stringa Signature String create prima della chiamata
          è uguale a quella restituita dal servizio

        - "Assert.assertEquals(signSHA256RSA(myResponse.get("signed_string").toString()),signSHA256RSA(input));" verifico se la firma della
          string creata prima della chiamata è uguale alla firma della stringa della risposta del servizio

        - "Assert.assertNotEquals(PUBLIC,myResponse.getJSONObject("authentication_key").get("role"));" verifico che il ruolo restituito non sia PUBLIC
          altrimenti ,come dice nella documentazione, vorrebbe dire che il servizio ha riconosciuto la keyId ma è sbagliata la firma

        - "Assert.assertTrue(sign.verify(b2));" faccio la verifica della chiave privata restituita dal servizio con la mia chiave pubblica

    Tutti i testi sono facilmente modificabili aggiungendo o togliendo degli header nella chiamata al metodo genericTest o
    modificando il metodo HTTP
