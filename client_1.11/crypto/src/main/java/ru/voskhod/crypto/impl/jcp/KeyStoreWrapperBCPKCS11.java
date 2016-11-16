package ru.voskhod.crypto.impl.jcp;

/**
 * Created by Gleb on 16.11.2016.
 */

import ru.voskhod.crypto.KeyStoreWrapper;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class KeyStoreWrapperBCPKCS11 implements KeyStoreWrapper {
    private final KeyStore ks;

    public KeyStoreWrapperBCPKCS11() throws Exception {
        ks = KeyStore.getInstance("HDImageStore");
        ks.load(null);
    }

    public PrivateKey getPrivateKey(String alias, char[] password, String keyPath) throws KeyStoreException,
            NoSuchAlgorithmException, UnrecoverableKeyException, IOException, CertificateException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(keyPath), password);
        Key key = ks.getKey(alias, password);
        return (PrivateKey) key;

    }

    public X509Certificate getX509Certificate(String alias) throws CertificateException, KeyStoreException {
        X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
        if (certificate == null)
            return null;
        return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }

    public KeyStore getKeyStore() {
        return ks;
    }
}
