/*
 * gtlscertificate-schannel.c
 *
 * Copyright (C) 2017 Sebastian Dröge <sebastian@centricular.com>
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

#include "gtlscertificate-schannel.h"
#include "gtlsdatabase-schannel.h"
#include "gtlsutils-schannel.h"

#include <ncrypt.h>
#include <stdio.h>
#include <wininet.h>

enum {
  PROP_CERTIFICATE = 1,
  PROP_CERTIFICATE_PEM,
  PROP_ISSUER,
  PROP_PRIVATE_KEY,
  PROP_PRIVATE_KEY_PEM,
  PROP_DATABASE,
  PROP_CERT_CONTEXT
};

struct _GTlsCertificateSchannel {
  GTlsCertificate parent;
};

typedef struct _GTlsCertificateSchannelPrivate {
  GTlsDatabase *database;
  PCCERT_CONTEXT cert_context;
  NCRYPT_KEY_HANDLE key_handle;
  GTlsCertificate *issuer;
} GTlsCertificateSchannelPrivate;

typedef struct _GTlsNCryptApi {
  SECURITY_STATUS (WINAPI *open_storage_provider) (NCRYPT_PROV_HANDLE *provider, LPCWSTR provider_name, DWORD flags);
  SECURITY_STATUS (WINAPI *import_key) (NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE import_key, LPCWSTR blob_type,
                                        NCryptBufferDesc *parameter_list, NCRYPT_KEY_HANDLE *key, PBYTE data,
                                        DWORD data_size, DWORD flags);
  SECURITY_STATUS (WINAPI *free_object) (NCRYPT_HANDLE object);
} GTlsNCryptApi;

static void g_tls_certificate_schannel_initable_interface_init (GInitableIface *iface);

static GTlsNCryptApi *g_tls_ncrypt_api_try_get (void);

G_DEFINE_TYPE_WITH_CODE (GTlsCertificateSchannel, g_tls_certificate_schannel, G_TYPE_TLS_CERTIFICATE,
                         G_ADD_PRIVATE (GTlsCertificateSchannel)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, g_tls_certificate_schannel_initable_interface_init))

/* Returns the length in byte of the wchar_t * */
static guint
wchar_len (const wchar_t *s)
{
  guint len = 0;
  guint8 *p = (guint8 *) s;

  while (*p || *(p+1)) {
    len += 2;
    p += 2;
  }

  return len;
}

static void
g_tls_certificate_schannel_import_private_key (GTlsCertificateSchannel * schannel, guint8 *der, gsize der_length)
{
  GTlsCertificateSchannelPrivate *priv = g_tls_certificate_schannel_get_instance_private (schannel);
  GTlsNCryptApi *ncrypt;
  NCRYPT_PROV_HANDLE provider;
  DWORD extra_get_name_flags;
  wchar_t *cert_name = NULL;
  DWORD cert_name_length;
  NCryptBuffer buffer;
  NCryptBufferDesc buffer_desc;
  CRYPT_KEY_PROV_INFO prov_info;

  ncrypt = g_tls_ncrypt_api_try_get ();
  if (ncrypt == NULL) {
    g_warning ("NCrypt API not available on this version of Windows");
    return;
  }

  if (ncrypt->open_storage_provider (&provider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
    g_warn_if_reached ();
    return;
  }

#ifdef CERT_NAME_SEARCH_ALL_NAMES_FLAG
  extra_get_name_flags = CERT_NAME_SEARCH_ALL_NAMES_FLAG;
#else
# define GLIB_SCHANNEL_CERT_NAME_SEARCH_ALL_NAMES_FLAG 0x2
  {
    OSVERSIONINFOEXW vi = { sizeof (vi), 0, };
    DWORD type_mask;
    DWORDLONG condition_mask;
    gboolean is_win8_or_newer;

    vi.dwMajorVersion = 6;
    vi.dwMinorVersion = 2;
    type_mask = VER_MAJORVERSION | VER_MINORVERSION;
    condition_mask = VerSetConditionMask (VerSetConditionMask (0,
                                          VER_MAJORVERSION, VER_GREATER_EQUAL),
                                          VER_MINORVERSION, VER_GREATER_EQUAL);
    is_win8_or_newer = VerifyVersionInfoW (&vi, type_mask, condition_mask);

    extra_get_name_flags = is_win8_or_newer ? GLIB_SCHANNEL_CERT_NAME_SEARCH_ALL_NAMES_FLAG : 0;
  }
#endif

  /* We store the key under the name of the certificate and attach
   * it under that name to the certificate. This way SChannel can
   * find it again at a later time */
  cert_name_length = CertGetNameStringW (priv->cert_context, CERT_NAME_DNS_TYPE,
                                         CERT_NAME_DISABLE_IE4_UTF8_FLAG | extra_get_name_flags,
                                         NULL, NULL, 0);
  if (cert_name_length > 1) {
    cert_name = g_new0 (wchar_t, cert_name_length);
    CertGetNameStringW (priv->cert_context, CERT_NAME_DNS_TYPE,
                        CERT_NAME_DISABLE_IE4_UTF8_FLAG | extra_get_name_flags,
                        NULL, cert_name, cert_name_length);
  }

  if (cert_name == NULL) {
    DWORD id_size;

    id_size = 0;
    CertGetCertificateContextProperty (priv->cert_context, CERT_KEY_IDENTIFIER_PROP_ID, NULL, &id_size);
    if (id_size > 0) {
      BYTE *id;
      DWORD i;

      id = g_new (BYTE, id_size);

      CertGetCertificateContextProperty (priv->cert_context, CERT_KEY_IDENTIFIER_PROP_ID, id, &id_size);

      cert_name_length = (id_size * 2) + 1;
      cert_name = g_new (wchar_t, cert_name_length);
      for (i = 0; i < id_size; i++)
        swprintf (cert_name + (i * 2), 2 + 1, L"%02x", id[i]);

      g_free (id);
    }
  }

  if (cert_name == NULL) {
    g_warn_if_reached ();
    goto out;
  }

  memset (&buffer_desc, 0, sizeof (buffer_desc));
  buffer_desc.ulVersion = NCRYPTBUFFER_VERSION;
  buffer_desc.cBuffers = 1;
  buffer_desc.pBuffers = &buffer;

  memset (&buffer, 0, sizeof (buffer));
  buffer.cbBuffer = cert_name_length * sizeof (wchar_t);
  buffer.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
  buffer.pvBuffer = cert_name;

  if (ncrypt->import_key (provider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &buffer_desc, &priv->key_handle,
                          der, der_length, 0) != ERROR_SUCCESS) {
    g_warn_if_fail (priv->key_handle);
    goto out;
  }

  CertSetCertificateContextProperty (priv->cert_context, CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                                     CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG, &priv->key_handle);

  memset (&prov_info, 0, sizeof (prov_info));
  prov_info.pwszContainerName = cert_name;
  prov_info.pwszProvName = MS_KEY_STORAGE_PROVIDER;
  prov_info.dwProvType = 0;
  prov_info.dwFlags = CERT_SET_KEY_PROV_HANDLE_PROP_ID | CERT_SET_KEY_CONTEXT_PROP_ID;
  CertSetCertificateContextProperty (priv->cert_context, CERT_KEY_PROV_INFO_PROP_ID,
                                     CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG, &prov_info);

out:
  g_free (cert_name);

  ncrypt->free_object (provider);
}

static void
g_tls_certificate_schannel_set_property (GObject * obj, guint property_id, const GValue *value, GParamSpec *pspec)
{
  GTlsCertificateSchannel *schannel = G_TLS_CERTIFICATE_SCHANNEL (obj);
  GTlsCertificateSchannelPrivate *priv = g_tls_certificate_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_CERTIFICATE: {
      GByteArray *bytes = g_value_get_boxed (value);

      if (priv->cert_context)
        return;

      if (bytes) {
        priv->cert_context = CertCreateCertificateContext (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                           bytes->data, bytes->len);
        g_warn_if_fail (priv->cert_context);
      }
      break;
    }
    case PROP_CERTIFICATE_PEM: {
      const gchar *pem;
      gunichar2 *pem_w;
      BYTE *der;
      DWORD length;

      if (priv->cert_context)
        return;

      pem = g_value_get_string (value);
      if (!pem)
        return;
      pem_w = g_utf8_to_utf16 (pem, -1, NULL, NULL, NULL);

      length = strlen (pem);
      der = g_new (BYTE, length);
      if (CryptStringToBinaryW (pem_w, 0, CRYPT_STRING_BASE64_ANY, der, &length, 0, 0)) {
        priv->cert_context = CertCreateCertificateContext (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                           der, length);
        g_warn_if_fail (priv->cert_context);
      }
      g_free (der);

      g_free (pem_w);

      break;
    }
    case PROP_ISSUER: {
      if (priv->issuer)
        g_object_unref (priv->issuer);
      priv->issuer = g_value_dup_object (value);
      break;
    }
    case PROP_PRIVATE_KEY: {
      GByteArray *bytes = g_value_get_boxed (value);

      if (priv->key_handle)
        return;

      g_assert (!bytes || priv->cert_context);

      if (!bytes)
        return;

      g_tls_certificate_schannel_import_private_key (schannel, bytes->data, bytes->len);
      break;
    }
    case PROP_PRIVATE_KEY_PEM: {
      const gchar *pem;
      gunichar2 *pem_w;
      BYTE *der;
      DWORD length;

      if (priv->key_handle)
        return;

      pem = g_value_get_string (value);
      g_assert (!pem || priv->cert_context);
      if (!pem)
        return;
      pem_w = g_utf8_to_utf16 (pem, -1, NULL, NULL, NULL);

      length = strlen (pem);
      der = g_new (BYTE, length);
      if (CryptStringToBinaryW (pem_w, 0, CRYPT_STRING_BASE64_ANY, der, &length, 0, 0)) {
        g_tls_certificate_schannel_import_private_key (schannel, der, length);
      } else {
        g_warn_if_reached ();
      }
      g_free (der);

      g_free (pem_w);

      break;
    }
    case PROP_DATABASE: {
      if (priv->database)
        g_object_unref (priv->database);
      priv->database = g_value_dup_object (value);
      break;
    }
    case PROP_CERT_CONTEXT: {
      if (priv->cert_context)
        return;
      priv->cert_context = g_value_get_pointer (value);
      break;
    }
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_certificate_schannel_get_property (GObject * obj, guint property_id, GValue *value, GParamSpec *pspec)
{
  GTlsCertificateSchannel *schannel = G_TLS_CERTIFICATE_SCHANNEL (obj);
  GTlsCertificateSchannelPrivate *priv = g_tls_certificate_schannel_get_instance_private (schannel);

  switch (property_id) {
    case PROP_CERTIFICATE: {

      if (priv->cert_context) {
        GByteArray *bytes = g_byte_array_sized_new (priv->cert_context->cbCertEncoded);

        g_byte_array_append (bytes, priv->cert_context->pbCertEncoded, priv->cert_context->cbCertEncoded);

        g_value_take_boxed (value, bytes);
      }

      break;
    }
    case PROP_CERTIFICATE_PEM: {
      if (priv->cert_context) {
        DWORD pem_length = 0;

        if (CryptBinaryToStringW (priv->cert_context->pbCertEncoded, priv->cert_context->cbCertEncoded,
                                  CRYPT_STRING_BASE64HEADER, NULL, &pem_length)) {
          gunichar2 *pem = g_new0 (gunichar2, pem_length);
          CryptBinaryToStringW (priv->cert_context->pbCertEncoded, priv->cert_context->cbCertEncoded,
                                CRYPT_STRING_BASE64HEADER, pem, &pem_length);
          g_value_take_string (value, g_utf16_to_utf8 (pem, -1, NULL, NULL, NULL));
          g_free (pem);
        }
      }

      break;
    }
    case PROP_ISSUER: {
      if (!priv->issuer && priv->database)
        priv->issuer = g_tls_database_lookup_certificate_issuer (priv->database, G_TLS_CERTIFICATE (schannel),
                                                                 NULL, 0, NULL, NULL);
      g_value_set_object (value, priv->issuer);
      break;
    }
    case PROP_DATABASE: {
      g_value_set_object (value, priv->database);
      break;
    }
    case PROP_CERT_CONTEXT: {
      g_value_set_pointer (value, (gpointer) priv->cert_context);
      break;
    }
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
g_tls_certificate_schannel_finalize (GObject * obj)
{
  GTlsCertificateSchannel *schannel = G_TLS_CERTIFICATE_SCHANNEL (obj);
  GTlsCertificateSchannelPrivate *priv = g_tls_certificate_schannel_get_instance_private (schannel);

  if (priv->database) {
    g_object_unref (priv->database);
    priv->database = NULL;
  }

  if (priv->issuer) {
    g_object_unref (priv->issuer);
    priv->issuer = NULL;
  }

  if (priv->cert_context) {
    CertFreeCertificateContext (priv->cert_context);
    priv->cert_context = NULL;
  }

  if (priv->key_handle) {
    g_tls_ncrypt_api_try_get ()->free_object (priv->key_handle);
    priv->key_handle = 0;
  }

  G_OBJECT_CLASS (g_tls_certificate_schannel_parent_class)->finalize (obj);
}

static GTlsCertificateFlags
g_tls_certificate_schannel_verify (GTlsCertificate *cert, GSocketConnectable *identity, GTlsCertificate *trusted_ca)
{
  GTlsCertificateSchannel *schannel = G_TLS_CERTIFICATE_SCHANNEL (cert);
  GTlsCertificateSchannelPrivate *priv = g_tls_certificate_schannel_get_instance_private (schannel);
  HCERTSTORE cert_store = NULL, trusted_store = NULL;
  GTlsCertificateSchannelPrivate *issuer_priv;
  GTlsCertificateFlags certificate_flags = 0;
  CERT_CHAIN_ENGINE_CONFIG engine_config;
  HCERTCHAINENGINE engine = NULL;
  PCCERT_CHAIN_CONTEXT chain_context = NULL;
  CERT_CHAIN_PARA chain_para;
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_policy_para;
  CERT_CHAIN_POLICY_PARA policy_para;
  CERT_CHAIN_POLICY_STATUS policy_status;
  wchar_t *wserver_name = NULL;

  /* Add all issuer certificates to a temporary database */
  cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  issuer_priv = priv;
  while (issuer_priv->issuer) {
    issuer_priv = g_tls_certificate_schannel_get_instance_private (G_TLS_CERTIFICATE_SCHANNEL (issuer_priv->issuer));
    CertAddCertificateContextToStore (cert_store, issuer_priv->cert_context, CERT_STORE_ADD_NEWER, NULL);
  }

  /* Add trusted CA, if any and all its issuer certificates to the trusted store */
  trusted_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  if (trusted_ca) {
    issuer_priv = g_tls_certificate_schannel_get_instance_private (G_TLS_CERTIFICATE_SCHANNEL (trusted_ca));
    CertAddCertificateContextToStore (trusted_store, issuer_priv->cert_context, CERT_STORE_ADD_NEWER, NULL);
    while (issuer_priv->issuer) {
      issuer_priv = g_tls_certificate_schannel_get_instance_private (G_TLS_CERTIFICATE_SCHANNEL (issuer_priv->issuer));
      CertAddCertificateContextToStore (trusted_store, issuer_priv->cert_context, CERT_STORE_ADD_NEWER, NULL);
    }
  }

  /* We create our own certificate chain engine here as we must only
   * use the certificate store(s) created above, not the system one
   */

  memset (&engine_config, 0, sizeof (engine_config));
  engine_config.cbSize = sizeof (engine_config);
  engine_config.hExclusiveRoot = trusted_store;

  if (!CertCreateCertificateChainEngine (&engine_config, &engine)) {
    g_warn_if_reached ();
    certificate_flags |= G_TLS_CERTIFICATE_GENERIC_ERROR;
    goto out;
  }

  memset (&chain_para, 0, sizeof (chain_para));
  chain_para.cbSize = sizeof (chain_para);

  if (!CertGetCertificateChain (engine, priv->cert_context, NULL, cert_store,
                                &chain_para, CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY |
                                             CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                                NULL, &chain_context)) {
    certificate_flags |= G_TLS_CERTIFICATE_GENERIC_ERROR;
    goto out;
  }

  certificate_flags |= g_tls_schannel_certificate_flags_from_chain (chain_context);

  if (identity) {
    gchar *server_name;

    server_name = g_tls_schannel_socket_connectable_to_string (identity);
    wserver_name = g_utf8_to_utf16 (server_name, -1, NULL, NULL, NULL);
    g_free (server_name);
  } else {
    wserver_name = NULL;
  }

  memset (&ssl_policy_para, 0, sizeof (ssl_policy_para));
  ssl_policy_para.cbStruct = sizeof (ssl_policy_para);
  /* Wrong usage is ignored because we don't know about the usage here */
  ssl_policy_para.fdwChecks = SECURITY_FLAG_IGNORE_WRONG_USAGE |
                              (trusted_ca ? 0 : SECURITY_FLAG_IGNORE_UNKNOWN_CA) |
                              (wserver_name ? 0 : SECURITY_FLAG_IGNORE_CERT_CN_INVALID);
  ssl_policy_para.pwszServerName = wserver_name;

  memset (&policy_para, 0, sizeof (policy_para));
  policy_para.cbSize = sizeof (policy_para);
  policy_para.pvExtraPolicyPara = &ssl_policy_para;

  memset (&policy_status, 0, sizeof (policy_status));
  policy_status.cbSize = sizeof (policy_status);

  /* If the certificate chain is known to be revoked or no revocation
   * information is known whatsoever, don't check for that (again) when
   * verifying the policy below */
  if ((certificate_flags & G_TLS_CERTIFICATE_REVOKED) ||
      (chain_context->TrustStatus.dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) ||
      (chain_context->TrustStatus.dwErrorStatus & CERT_TRUST_IS_OFFLINE_REVOCATION)) {
    ssl_policy_para.fdwChecks |= SECURITY_FLAG_IGNORE_REVOCATION;
    policy_para.dwFlags |= CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS;
  }

  /* And don't check for other things we already know have failed */
  if ((certificate_flags & G_TLS_CERTIFICATE_EXPIRED)) {
    LONG cmp;

    ssl_policy_para.fdwChecks |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    policy_para.dwFlags |= CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG
                        |  CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS;

    /* Both flags are set by the code above as we don't know, so check here
     * whether the certificate is not activated yet or expired */
    cmp = CertVerifyTimeValidity (NULL, priv->cert_context->pCertInfo);
    if (cmp == 1)
      certificate_flags &= ~G_TLS_CERTIFICATE_NOT_ACTIVATED;
    else if (cmp == -1)
      certificate_flags &= ~G_TLS_CERTIFICATE_EXPIRED;
    /* Otherwise it must be any of the certificates in the chain or nesting is
     * wrong, for which we have no way of specifying that in GIO */
  }

  if ((certificate_flags & G_TLS_CERTIFICATE_UNKNOWN_CA)) {
    ssl_policy_para.fdwChecks |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    policy_para.dwFlags |= CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG;
  }

  if (!CertVerifyCertificateChainPolicy (CERT_CHAIN_POLICY_SSL, chain_context, &policy_para, &policy_status)) {
    certificate_flags |= G_TLS_CERTIFICATE_GENERIC_ERROR;
    goto out;
  }

  certificate_flags |= g_tls_schannel_certificate_flags_from_policy_status (&policy_status);

out:
  g_free (wserver_name);
  if (chain_context)
    CertFreeCertificateChain (chain_context);
  if (engine)
    CertFreeCertificateChainEngine (engine);
  if (cert_store)
    CertCloseStore (cert_store, 0);
  if (trusted_store)
    CertCloseStore (trusted_store, 0);

  return certificate_flags;
}

static void
g_tls_certificate_schannel_class_init (GTlsCertificateSchannelClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;
  GTlsCertificateClass *certificate_class = G_TLS_CERTIFICATE_CLASS (klass);

  gobject_class->set_property = g_tls_certificate_schannel_set_property;
  gobject_class->get_property = g_tls_certificate_schannel_get_property;
  gobject_class->finalize = g_tls_certificate_schannel_finalize;

  g_object_class_override_property (gobject_class, PROP_CERTIFICATE, "certificate");
  g_object_class_override_property (gobject_class, PROP_CERTIFICATE_PEM, "certificate-pem");
  g_object_class_override_property (gobject_class, PROP_ISSUER, "issuer");
  g_object_class_override_property (gobject_class, PROP_PRIVATE_KEY, "private-key");
  g_object_class_override_property (gobject_class, PROP_PRIVATE_KEY_PEM, "private-key-pem");

  g_object_class_install_property (gobject_class, PROP_DATABASE,
                                   g_param_spec_object ("database", "Database", "Certificate database",
                                                        G_TYPE_TLS_DATABASE_SCHANNEL,
                                                        G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, PROP_CERT_CONTEXT,
                                   g_param_spec_pointer ("cert-context", "Cert Context", "Certificate context",
                                                         G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE |
                                                         G_PARAM_STATIC_STRINGS));

  certificate_class->verify = g_tls_certificate_schannel_verify;
}

static gboolean
g_tls_certificate_schannel_initable_init (GInitable *initable, GCancellable *cancellable, GError **error)
{
  return TRUE;
}

static void
g_tls_certificate_schannel_initable_interface_init (GInitableIface *iface)
{
  iface->init = g_tls_certificate_schannel_initable_init;
}

static void
g_tls_certificate_schannel_init (GTlsCertificateSchannel *schannel)
{
}

GTlsCertificate *
g_tls_certificate_schannel_new_from_context (GTlsDatabase * database, PCCERT_CONTEXT cert_context)
{
  return g_object_new (G_TYPE_TLS_CERTIFICATE_SCHANNEL, "database", database, "cert-context", cert_context, NULL);
}

PCCERT_CONTEXT
g_tls_certificate_schannel_get_context (GTlsCertificate * certificate)
{
  GTlsCertificateSchannel *schannel = G_TLS_CERTIFICATE_SCHANNEL (certificate);
  GTlsCertificateSchannelPrivate *priv = g_tls_certificate_schannel_get_instance_private (schannel);

  return priv->cert_context;
}

static GTlsNCryptApi *
g_tls_ncrypt_api_try_get (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value)) {
    GTlsNCryptApi *ncrypt = NULL;
    HMODULE module;

    module = LoadLibraryW (L"ncrypt.dll");
    if (module != NULL) {
      ncrypt = g_slice_new (GTlsNCryptApi);
      ncrypt->open_storage_provider = (gpointer) GetProcAddress (module, "NCryptOpenStorageProvider");
      ncrypt->import_key = (gpointer) GetProcAddress (module, "NCryptImportKey");
      ncrypt->free_object = (gpointer) GetProcAddress (module, "NCryptFreeObject");
    }

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (ncrypt) + 1);
  }

  return (GTlsNCryptApi *) GSIZE_TO_POINTER (gonce_value - 1);
}
