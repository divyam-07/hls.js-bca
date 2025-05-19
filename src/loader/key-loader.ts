import { LoadError } from './fragment-loader';
import { ErrorDetails, ErrorTypes } from '../errors';
import type { HlsConfig } from '../config';
import type { LevelKey } from './level-key';
import type EMEController from '../controller/eme-controller';
import type { MediaKeySessionContext } from '../controller/eme-controller';
import type { Fragment } from '../loader/fragment';
import type { ComponentAPI } from '../types/component-api';
import type { KeyLoadedData } from '../types/events';
import type {
  KeyLoaderContext,
  Loader,
  LoaderCallbacks,
  LoaderConfiguration,
  LoaderResponse,
  LoaderStats,
  PlaylistLevelType,
} from '../types/loader';
import type { KeySystemFormats } from '../utils/mediakeys-helper';

export interface KeyLoaderInfo {
  decryptdata: LevelKey;
  keyLoadPromise: Promise<KeyLoadedData> | null;
  loader: Loader<KeyLoaderContext> | null;
  mediaKeySessionContext: MediaKeySessionContext | null;
}
export default class KeyLoader implements ComponentAPI {
  private readonly config: HlsConfig;
  public keyUriToKeyInfo: { [keyuri: string]: KeyLoaderInfo } = {};
  public emeController: EMEController | null = null;

  constructor(config: HlsConfig) {
    this.config = config;
  }

  abort(type?: PlaylistLevelType) {
    for (const uri in this.keyUriToKeyInfo) {
      const loader = this.keyUriToKeyInfo[uri].loader;
      if (loader) {
        if (type && type !== loader.context?.frag.type) {
          return;
        }
        loader.abort();
      }
    }
  }

  detach() {
    for (const uri in this.keyUriToKeyInfo) {
      const keyInfo = this.keyUriToKeyInfo[uri];
      // Remove cached EME keys on detach
      if (
        keyInfo.mediaKeySessionContext ||
        keyInfo.decryptdata.isCommonEncryption
      ) {
        delete this.keyUriToKeyInfo[uri];
      }
    }
  }

  destroy() {
    this.detach();
    for (const uri in this.keyUriToKeyInfo) {
      const loader = this.keyUriToKeyInfo[uri].loader;
      if (loader) {
        loader.destroy();
      }
    }
    this.keyUriToKeyInfo = {};
  }

  createKeyLoadError(
    frag: Fragment,
    details: ErrorDetails = ErrorDetails.KEY_LOAD_ERROR,
    error: Error,
    networkDetails?: any,
    response?: { url: string; data: undefined; code: number; text: string },
  ): LoadError {
    return new LoadError({
      type: ErrorTypes.NETWORK_ERROR,
      details,
      fatal: false,
      frag,
      response,
      error,
      networkDetails,
    });
  }

  loadClear(
    loadingFrag: Fragment,
    encryptedFragments: Fragment[],
  ): void | Promise<void> {
    if (this.emeController && this.config.emeEnabled) {
      // access key-system with nearest key on start (loaidng frag is unencrypted)
      const { sn, cc } = loadingFrag;
      for (let i = 0; i < encryptedFragments.length; i++) {
        const frag = encryptedFragments[i];
        if (
          cc <= frag.cc &&
          (sn === 'initSegment' || frag.sn === 'initSegment' || sn < frag.sn)
        ) {
          this.emeController
            .selectKeySystemFormat(frag)
            .then((keySystemFormat) => {
              frag.setKeyFormat(keySystemFormat);
            });
          break;
        }
      }
    }
  }

  load(frag: Fragment): Promise<KeyLoadedData> {
    if (
      !frag.decryptdata &&
      frag.encrypted &&
      this.emeController &&
      this.config.emeEnabled
    ) {
      // Multiple keys, but none selected, resolve in eme-controller
      return this.emeController
        .selectKeySystemFormat(frag)
        .then((keySystemFormat) => {
          return this.loadInternal(frag, keySystemFormat);
        });
    }

    return this.loadInternal(frag);
  }

  loadInternal(
    frag: Fragment,
    keySystemFormat?: KeySystemFormats,
  ): Promise<KeyLoadedData> {
    if (keySystemFormat) {
      frag.setKeyFormat(keySystemFormat);
    }
    const decryptdata = frag.decryptdata;
    if (!decryptdata) {
      const error = new Error(
        keySystemFormat
          ? `Expected frag.decryptdata to be defined after setting format ${keySystemFormat}`
          : 'Missing decryption data on fragment in onKeyLoading',
      );
      return Promise.reject(
        this.createKeyLoadError(frag, ErrorDetails.KEY_LOAD_ERROR, error),
      );
    }
    const uri = decryptdata.uri;
    if (!uri) {
      return Promise.reject(
        this.createKeyLoadError(
          frag,
          ErrorDetails.KEY_LOAD_ERROR,
          new Error(`Invalid key URI: "${uri}"`),
        ),
      );
    }
    let keyInfo = this.keyUriToKeyInfo[uri];

    if (keyInfo?.decryptdata.key) {
      decryptdata.key = keyInfo.decryptdata.key;
      return Promise.resolve({ frag, keyInfo });
    }
    // Return key load promise as long as it does not have a mediakey session with an unusable key status
    if (keyInfo?.keyLoadPromise) {
      switch (keyInfo.mediaKeySessionContext?.keyStatus) {
        case undefined:
        case 'status-pending':
        case 'usable':
        case 'usable-in-future':
          return keyInfo.keyLoadPromise.then((keyLoadedData) => {
            // Return the correct fragment with updated decryptdata key and loaded keyInfo
            decryptdata.key = keyLoadedData.keyInfo.decryptdata.key;
            return { frag, keyInfo };
          });
      }
      // If we have a key session and status and it is not pending or usable, continue
      // This will go back to the eme-controller for expired keys to get a new keyLoadPromise
    }

    // Load the key or return the loading promise
    keyInfo = this.keyUriToKeyInfo[uri] = {
      decryptdata,
      keyLoadPromise: null,
      loader: null,
      mediaKeySessionContext: null,
    };

    switch (decryptdata.method) {
      case 'ISO-23001-7':
      case 'SAMPLE-AES':
      case 'SAMPLE-AES-CENC':
      case 'SAMPLE-AES-CTR':
        if (decryptdata.keyFormat === 'identity') {
          // loadKeyHTTP handles http(s) and data URLs
          return this.loadKeyHTTP(keyInfo, frag);
        }
        return this.loadKeyEME(keyInfo, frag);
      case 'AES-128':
      case 'AES-256':
      case 'AES-256-CTR':
        return this.loadKeyHTTP(keyInfo, frag);
      default:
        return Promise.reject(
          this.createKeyLoadError(
            frag,
            ErrorDetails.KEY_LOAD_ERROR,
            new Error(
              `Key supplied with unsupported METHOD: "${decryptdata.method}"`,
            ),
          ),
        );
    }
  }

  loadKeyEME(keyInfo: KeyLoaderInfo, frag: Fragment): Promise<KeyLoadedData> {
    const keyLoadedData: KeyLoadedData = { frag, keyInfo };
    if (this.emeController && this.config.emeEnabled) {
      const keySessionContextPromise =
        this.emeController.loadKey(keyLoadedData);
      if (keySessionContextPromise) {
        return (keyInfo.keyLoadPromise = keySessionContextPromise.then(
          (keySessionContext) => {
            keyInfo.mediaKeySessionContext = keySessionContext;
            return keyLoadedData;
          },
        )).catch((error) => {
          // Remove promise for license renewal or retry
          keyInfo.keyLoadPromise = null;
          throw error;
        });
      }
    }
    return Promise.resolve(keyLoadedData);
  }

  async loadKeyHTTP(
    keyInfo: KeyLoaderInfo,
    frag: Fragment,
  ): Promise<KeyLoadedData> {
    const config = this.config;
    const Loader = config.loader;
    const keyLoader = new Loader(config) as Loader<KeyLoaderContext>;
    frag.keyLoader = keyInfo.loader = keyLoader;

    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt'],
    );

    const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(spki)));

    return (keyInfo.keyLoadPromise = new Promise((resolve, reject) => {
      const loaderContext: KeyLoaderContext = {
        keyInfo,
        frag,
        responseType: 'arraybuffer',
        url: keyInfo.decryptdata.uri,
        headers: {
          'X-Public-Key': publicKeyBase64,
        },
      };

      const loaderConfig: LoaderConfiguration = {
        timeout: 6000,
        maxRetry: 0,
        retryDelay: 0,
        maxRetryDelay: 0,
        loadPolicy: config.keyLoadPolicy.default,
      };

      const loaderCallbacks: LoaderCallbacks<KeyLoaderContext> = {
        onSuccess: async (response, stats, context, networkDetails) => {
          try {
            const encryptedKey = new Uint8Array(response.data as ArrayBuffer);

            // 3. Decrypt key using privateKey
            const decryptedKey = await crypto.subtle.decrypt(
              { name: 'RSA-OAEP' },
              keyPair.privateKey,
              encryptedKey,
            );

            const keyUint8 = new Uint8Array(decryptedKey);

            frag.decryptdata!.key = keyInfo.decryptdata.key = keyUint8;

            frag.keyLoader = null;
            keyInfo.loader = null;
            resolve({ frag, keyInfo });
          } catch (err) {
            reject(
              this.createKeyLoadError(
                frag,
                ErrorDetails.KEY_LOAD_ERROR,
                new Error('RSA decryption failed: ' + err),
                networkDetails,
              ),
            );
          }
        },

        onError: (response, context, networkDetails) => {
          this.resetLoader(context);
          reject(
            this.createKeyLoadError(
              frag,
              ErrorDetails.KEY_LOAD_ERROR,
              new Error(`Key HTTP Error ${response.code}: ${response.text}`),
              networkDetails,
            ),
          );
        },

        onTimeout: (stats, context, networkDetails) => {
          this.resetLoader(context);
          reject(
            this.createKeyLoadError(
              frag,
              ErrorDetails.KEY_LOAD_TIMEOUT,
              new Error('Key request timed out'),
              networkDetails,
            ),
          );
        },

        onAbort: (stats, context, networkDetails) => {
          this.resetLoader(context);
          reject(
            this.createKeyLoadError(
              frag,
              ErrorDetails.INTERNAL_ABORTED,
              new Error('Key request aborted'),
              networkDetails,
            ),
          );
        },
      };

      keyLoader.load(loaderContext, loaderConfig, loaderCallbacks);
    }));
  }

  private resetLoader(context: KeyLoaderContext) {
    const { frag, keyInfo, url: uri } = context;
    const loader = keyInfo.loader;
    if (frag.keyLoader === loader) {
      frag.keyLoader = null;
      keyInfo.loader = null;
    }
    delete this.keyUriToKeyInfo[uri];
    if (loader) {
      loader.destroy();
    }
  }
}
