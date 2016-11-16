package ru.voskhod.crypto;

import org.w3c.dom.Element;

public class Main {

    public static final String TEST_M = "<ns2:MessageTypeSelector xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\" xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" Id=\"SIGNED_BY_CALLER\"><ns2:Timestamp>2014-08-14T08:19:28.972+04:00</ns2:Timestamp></ns2:MessageTypeSelector>";
    public static final String TEST_S = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\" xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411\"/><ds:Reference URI=\"#SIGNED_BY_CALLER\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr3411\"/><ds:DigestValue>5dinABQ/YGiLXUgU3reL/KEWBktTFcnmnmYQRpflkdI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>q9Ya909nzP4k5pLuVmXNqP3aiHdGZaQ7WaN7bbtseKG6UMBadPODy7g0zI0u96HaG3WfY9SQJXXZ+LyBm6x5aQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBVzCCAQSgAwIBAgIEdNpCKTAKBgYqhQMCAgMFADAyMRAwDgYDVQQLEwdTWVNURU0xMREwDwYDVQQKEwhlbXUtdGVzdDELMAkGA1UEBhMCUlUwHhcNMTQwNzA4MTMxNzQ1WhcNMTQxMDA2MTMxNzQ1WjAyMRAwDgYDVQQLEwdTWVNURU0xMREwDwYDVQQKEwhlbXUtdGVzdDELMAkGA1UEBhMCUlUwYzAcBgYqhQMCAhMwEgYHKoUDAgIjAQYHKoUDAgIeAQNDAARAgK00AVZSaE71BMMXbUq77hh1/1OKVqWJmO/tkK4nI7cUBeOlTRJiGDwZbd84v97PBN1ISrakO14m+OAqL+1NfDAKBgYqhQMCAgMFAANBAF3Q42Q0Y2w2abVtY7X5twIJHQ+Q8w3PA/KFIRCO+QWT739UFPNTmwUMvFiS9vqIJFUqiqG2cBT1PSP59sJpiNM=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>";

    public static final String TEST_M_2 = "<SenderProvidedRequestData xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" wss:Id=\"SenderProvidedRequestData\" xmlns:wss=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"><MessageID>38e046d2-21f8-11e4-805e-c76716e45fb6</MessageID><MessagePrimaryContent xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"><ns1:BreachRequest xmlns:ns1=\"urn://x-artefacts-gibdd-gov-ru/breach/root/1.0\"><ns1:RequestedInformation><ns2:RegPointNum xmlns:ns2=\"urn://x-artefacts-gibdd-gov-ru/breach/commons/1.0\">78557</ns2:RegPointNum></ns1:RequestedInformation><ns1:Governance><ns3:Name xmlns:ns3=\"urn://x-artefacts-gibdd-gov-ru/breach/commons/1.0\">11111</ns3:Name><ns4:Code xmlns:ns4=\"urn://x-artefacts-gibdd-gov-ru/breach/commons/1.0\">GIBDD</ns4:Code><ns5:OfficialPerson xmlns:ns5=\"urn://x-artefacts-gibdd-gov-ru/breach/commons/1.0\"><ns6:FamilyName xmlns:ns6=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\">222222</ns6:FamilyName><ns7:FirstName xmlns:ns7=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\">333333</ns7:FirstName><ns8:Patronymic xmlns:ns8=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\">444444</ns8:Patronymic></ns5:OfficialPerson></ns1:Governance></ns1:BreachRequest></MessagePrimaryContent></SenderProvidedRequestData>";
    public static final String TEST_S_2 = "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411\"/><Reference URI=\"#SenderProvidedRequestData\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr3411\"/><DigestValue>W7natCiXacUz9rGcFuPWsQIodHZ4I4Bn8Jd5I1XYjus=</DigestValue></Reference></SignedInfo><SignatureValue>3ycglxn8IkzGzShjKuVxQJUf1lpbt/6zGtlGTKMamJlWvWkgTOLitp5C3RZ69YDT0bUIwTq9iIV6O3tyQrqNYQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature>";

    public static void main(String[] args) throws Exception {
        //DigitalSignatureFactory.init("DIGT");
        DigitalSignatureFactory.init("BC_PKCS12");
        DigitalSignatureProcessor dsp = DigitalSignatureFactory.getDigitalSignatureProcessor();
        KeyStoreWrapper ksw = DigitalSignatureFactory.getKeyStoreWrapper();
        Element e = XMLTransformHelper.buildDocumentFromString(TEST_SIGN).getDocumentElement();
        /*dsp.signXMLDSigEnveloped(e, ksw.getPrivateKey("REGISTRY\\\\LOSKUTOV2", "123456".toCharArray()), ksw.getX509Certificate("REGISTRY\\\\LOSKUTOV2"));
        System.out.println(XMLTransformHelper.elementToString(e));*/
        System.out.println(XMLTransformHelper.elementToString(dsp.signXMLDSigDetached(e, null, ksw.getPrivateKey("REGISTRY\\\\LOSKUTOV2", "123456".toCharArray()), ksw.getX509Certificate("REGISTRY\\\\LOSKUTOV2"))));
        // DigitalSignatureFactory.getDigitalSignatureProcessor().validateXMLDSigEnvelopedSignature(XMLTransformHelper.buildDocumentFromString(TEST_FALSE).getDocumentElement());
        //DigitalSignatureFactory.getDigitalSignatureProcessor().validateXMLDSigDetachedSignature(XMLTransformHelper.buildDocumentFromString(TEST_M_2).getDocumentElement(), XMLTransformHelper.buildDocumentFromString(TEST_S_2).getDocumentElement());
    }
}
