package csrjonny;

// Log4J
// Mehrsprachigkeit (properties file)
// konfigurierbare attribute

import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Date;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class Start {
	private static PrivateKey privkey;
	private static PublicKey pubkey; 

	public Start() {
		// TODO Auto-generated constructor stub
	}

	public static void main(String[] args) {
		System.out.println("Starting");
    	Provider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    	Security.insertProviderAt(bc, 1);
    	try {
			try {
				generateCSR();
				testBouncyCastle();
			} catch (OperatorCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	wipeKeys();
	}

	
    private static void generateKeyPair() throws NoSuchAlgorithmException {
    	Provider provider = Security.getProvider("bc");
    	Security.addProvider(provider);
    	
    	SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
    	// final KeyPairGenerator keyPairGen = ECKeyPairGenerator
        		//.getInstance(provider, secureRandom);
    	// final KeyPair keyPair = keyPairGen.generateKeyPair();
    	// this.privkey = keyPair.getPrivate();
    	// this.pubkey  = keyPair.getPublic();
    	// var privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        // var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
    	
    }
    
    private static void generateCSR() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException, IOException {
    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keypair = keyGen.genKeyPair();
        PrivateKey privateKey = keypair.getPrivate();
        PublicKey publicKey = keypair.getPublic();
        
        // Metainfo
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);
        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.CN, "test request");
        nameBuilder.addRDN(BCStyle.C, "UK");
        nameBuilder.addRDN(BCStyle.E,"qwerasd@gmail.com");
        nameBuilder.addRDN(BCStyle.GENDER,"M");
        X500Name name = nameBuilder.build();
        // ^^^^^^^^^^^^^^^^^^ Metainfo        
        

        // PKCS10 Builder --->
        
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder( 
        		name, keypair.getPublic()
        );
        
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(keypair.getPrivate());

        // Extensions
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        
        
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        // ^^^^^^^^^^^^^^^^^^^^^^^^^ Extensions
        
        // PKCS 10 Builder ^^^^^^^^^^^^^^^^^^^^^
        
        // Read X500 Info from CSR
        X500NameStyle x500NameStyle = RFC4519Style.INSTANCE;
        X500Name x500 = csr.getSubject();
        RDN[] rdns = x500.getRDNs();
        for ( RDN rdn : rdns ) {
            for ( AttributeTypeAndValue attribute : rdn.getTypesAndValues() ) {
                System.out.printf( "%s (%s) = %s%n",
                        x500NameStyle.oidToDisplayName( attribute.getType() ),
                        attribute.getType(),
                        attribute.getValue()
                );
            }
        }
        // Read X500 Info from CSR
        System.out.println(csr.getSubject());
        
        // Read Extensions #####################################################################################################################---->
        Attribute[] attributes = csr.getAttributes();

        Attribute oneAttr = attributes[0];

        ASN1ObjectIdentifier oneAttrType = oneAttr.getAttrType();

        // Wir suchen nach dem Extension ObjectIdentifier 
        if (oneAttr.getAttrType().equals( PKCSObjectIdentifiers.pkcs_9_at_extensionRequest )) {
        	// Das hier ist eine echte Extension, weil Object Identifier = 1.2.840.113549.1.9.14 = pkcs_9_at_extensionRequest
        	System.out.println("  + PKCS9 Extension Request:");

        	// Extensions extrahieren
        	Extensions extensionSet =  (Extensions) oneAttr.getAttrValues().getObjectAt(0);
        	
        	// OIDs extrahieren
        	ASN1ObjectIdentifier[] extensionOIDs = extensionSet.getExtensionOIDs();
        	
        	for (int i = 0; i < extensionOIDs.length; i++) {
            	System.out.println("  | OID:   " +     extensionOIDs[i] );
            	System.out.println("  | Value: " +     extensionSet.getExtensionParsedValue(extensionOIDs[i]));
        	}
        	

            // The X509Extensions are contained as a value of the ASN.1 Set.
            // Assume that it is the first value of the set.
            //if (attributeValues.size() >= 1) {
            //	certificateRequestExtensions = new X509Extensions( (ASN1Sequence) attributeValues.getObjectAt( 0 ) );
               // No need to search any more.
            //   break;
        }
        
        ASN1Set attrValues = oneAttr.getAttrValues();
        ASN1Encodable attSequence = attrValues.getObjectAt(0);
        
////        ASN1Sequence sequence = (ASN1Sequence) attrValues.getObjectAt( 0 );
////        ASN1Encodable[] attributVals;
////        
////        
////        System.out.println("Attributes: ");
////        for (int i = 0; i < attributes.length; i++) {
////        	String attributId = attributes[i].getAttrType().getId();
////        	System.out.println("    +"  + attributId);
////        	
////        	// TODO: ICH will gedebugged werden um die verschachtelung zu sehen
////        	attributVals = attributes[i].getAttributeValues();
////        	
////        	
////        	for (ASN1Encodable asn1Encodable : attributVals) {
////        		System.out.println("    +"  + asn1Encodable);	
////			}
////        	
////		}
////        System.out.println("Signaturalgorithmus: " + csr.getSignatureAlgorithm().getAlgorithm().toString());
        System.out.println();
        
        // Read Extensions ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^#######################################################################################
        
        StringWriter sw = new StringWriter();

        try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
            jpw.writeObject(csr);
        }

        String pem = sw.toString();
        System.out.println(pem);
        
////        PKCS10CertificationRequest csr = new PKCS10CertificationRequest( 
////                           "SHA1withRSA",
////                           subject,
////                           keypair.getPublic(),
////                           null,
////                           keypair.getPrivate()
////                );
 
        //byte[] outBytes = csr.getEncoded();
        //FileOutputStream f = new FileOutputStream("outfile.csr_bin");
        //f.write(outBytes);
        //f.close();
 
        // FileWriter fw = new FileWriter("outfile.csr");
        //PemWriter pm = new PEMWriter(fw);

        //pm.writeObject(csr);
        //pm.close();
        //fw.close();
    }
    
    
////    /**
////     * Gets the X509 Extensions contained in a CSR (Certificate Signing Request).
////     *
////     * @param certificateSigningRequest the CSR.
////     * @return the X509 Extensions in the request.
////     * @throws CertificateException if the extensions could not be found.
////     */
////    X509Extensions getX509ExtensionsFromCsr( final PKCS10CertificationRequest certificateSigningRequest ) throws CertificateException
////    {
////       final CertificationRequestInfo certificationRequestInfo = certificateSigningRequest
////       final ASN1Set attributesAsn1Set = certificationRequestInfo.getAttributes();
////
////       // The `Extension Request` attribute is contained within an ASN.1 Set,
////       // usually as the first element.
////       X509Extensions certificateRequestExtensions = null;
////       for (int i = 0; i < attributesAsn1Set.size(); ++i)
////       {
////          // There should be only only one attribute in the set. (that is, only
////          // the `Extension Request`, but loop through to find it properly)
////          final DEREncodable derEncodable = attributesAsn1Set.getObjectAt( i );
////          if (derEncodable instanceof DERSequence)
////          {
////             final Attribute attribute = new Attribute( (DERSequence) attributesAsn1Set.getObjectAt( i ) );
////
////             if (attribute.getAttrType().equals( PKCSObjectIdentifiers.pkcs_9_at_extensionRequest )) {
////                // The `Extension Request` attribute is present.
////                final ASN1Set attributeValues = attribute.getAttrValues();
////
////                // The X509Extensions are contained as a value of the ASN.1 Set.
////                // Assume that it is the first value of the set.
////                if (attributeValues.size() >= 1) {
////                	certificateRequestExtensions = new X509Extensions( (ASN1Sequence) attributeValues.getObjectAt( 0 ) );
////                   // No need to search any more.
////                   break;
////                }
////             }
////          }
////       }
////
////       if (null == certificateRequestExtensions)
////       {
////          throw new CertificateException( "Could not obtain X509 Extensions from the CSR" );
////       }
////
////       return certificateRequestExtensions;
////    }
    
    
    
    private static void wipeKeys() {
    	privkey = null;
    	pubkey = null;
    }

////    public PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pem) throws Exception {
////        PKCS10CertificationRequest csr = null;
////        PemHeader reader = new PemHeader(new StringReader(pem));
////        try {
////            Object parsedObj = reader.readObject();
////
////            if (parsedObj instanceof PKCS10CertificationRequest) {
////                csr = (PKCS10CertificationRequest) parsedObj;
////            }
////        } catch (IOException ex) {
////            ex.printStackTrace();
////        } finally {
////            reader.close();
////        }
////
////        return csr;
////    }
    
    public static void testBouncyCastle()  {
		////    	https://tools.ietf.org/html/rfc8032
		////    		   -----TEST abc
		////
		////    		   ALGORITHM:
		////    		   Ed25519ph
		////
		////    		   SECRET KEY:
		////    		   833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42
		////
		////    		   PUBLIC KEY:
		////    		   ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf
		////
		////    		   MESSAGE (length 3 bytes):
		////    		   616263
		////
		////    		   SIGNATURE:
		////    		   98a70222f0b8121aa9d30f813d683f80
		////    		   9e462b469c7ff87639499bb94e6dae41
		////    		   31f85042463c2a355a2003d062adf5aa
		////    		   a10b8c61e636062aaad11c2a26083406
    		
    	byte[] msg = {0x61, 0x62, 0x63};
        byte[] privateKeyBytes = toByteArray("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
        byte[] publicKeyBytes = toByteArray("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    	
        // Test case defined in https://tools.ietf.org/html/rfc8037
		////        byte[] msg = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc".getBytes(StandardCharsets.UTF_8);
		////        String expectedSig = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
		////
		////        byte[] privateKeyBytes = Base64.getUrlDecoder().decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
		////        byte[] publicKeyBytes = Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);

        // Generate new signature
        byte[] empty = {};
        Signer signer = new Ed25519phSigner(empty);
        signer.init(true, privateKey);
        signer.update(msg, 0, msg.length);
        byte[] signature = {0x00};
		try {
			signature = signer.generateSignature();
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
        String actualSignature = toHexString(signature);
System.out.println("actualSignature = " + actualSignature);
        //  LOG.info("Expected signature: {}", expectedSig);
        //  LOG.info("Actual signature  : {}", actualSignature);
    }
    

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }
    
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ ");
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        sb.append("]");
        return sb.toString();
    }

}  

