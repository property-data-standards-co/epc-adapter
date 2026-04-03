/**
 * Client for the UK EPC Register API.
 * https://epc.opendatacommunities.org/docs/api/domestic
 */

export interface EpcRecord {
  'lmk-key': string;
  uprn: string;
  address1: string;
  address2: string;
  address3: string;
  postcode: string;
  posttown: string;
  'current-energy-rating': string;
  'current-energy-efficiency': string;
  'potential-energy-rating': string;
  'potential-energy-efficiency': string;
  'property-type': string;
  'built-form': string;
  'floor-description': string;
  'walls-description': string;
  'roof-description': string;
  'windows-description': string;
  'main-heating-description': string;
  'main-fuel': string;
  'total-floor-area': string;
  'inspection-date': string;
  'lodgement-date': string;
  'lodgement-datetime': string;
  'environment-impact-current': string;
  'environment-impact-potential': string;
  'energy-consumption-current': string;
  'energy-consumption-potential': string;
  'co2-emissions-current': string;
  'co2-emiss-curr-per-floor-area': string;
  'co2-emissions-potential': string;
  'lighting-cost-current': string;
  'lighting-cost-potential': string;
  'heating-cost-current': string;
  'heating-cost-potential': string;
  'hot-water-cost-current': string;
  'hot-water-cost-potential': string;
  constituency: string;
  'local-authority': string;
  county: string;
  [key: string]: string;
}

export interface EpcSearchResponse {
  rows: EpcRecord[];
  'column-names': string[];
}

export class EpcApiError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
  ) {
    super(message);
    this.name = 'EpcApiError';
  }
}

export interface EpcClientOptions {
  email: string;
  apiKey: string;
  baseUrl?: string;
  maxRetries?: number;
  fetchFn?: typeof fetch;
}

export class EpcClient {
  private readonly authHeader: string;
  private readonly baseUrl: string;
  private readonly maxRetries: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: EpcClientOptions) {
    const token = Buffer.from(`${options.email}:${options.apiKey}`).toString('base64');
    this.authHeader = `Basic ${token}`;
    this.baseUrl = options.baseUrl ?? 'https://epc.opendatacommunities.org/api/v1';
    this.maxRetries = options.maxRetries ?? 2;
    this.fetchFn = options.fetchFn ?? fetch;
  }

  /**
   * Search for EPCs by UPRN. Returns the most recent certificate.
   * @returns The raw EPC record and the raw JSON response body.
   */
  async searchByUprn(uprn: string): Promise<{ record: EpcRecord; rawBody: string }> {
    const url = `${this.baseUrl}/domestic/search?uprn=${encodeURIComponent(uprn)}&size=1`;
    const response = await this.fetchWithRetry(url);
    const rawBody = await response.text();
    const data = JSON.parse(rawBody) as EpcSearchResponse;

    if (!data.rows || data.rows.length === 0) {
      throw new EpcApiError(`No EPC found for UPRN ${uprn}`, 404);
    }

    return { record: data.rows[0], rawBody };
  }

  /**
   * Fetch a specific EPC certificate by LMK key.
   * @returns The raw EPC record and the raw JSON response body.
   */
  async getCertificate(lmkKey: string): Promise<{ record: EpcRecord; rawBody: string }> {
    const url = `${this.baseUrl}/domestic/certificate/${encodeURIComponent(lmkKey)}`;
    const response = await this.fetchWithRetry(url);
    const rawBody = await response.text();
    const data = JSON.parse(rawBody) as EpcSearchResponse;

    // The certificate endpoint returns { rows: [record], column-names: [...] }
    if (!data.rows || data.rows.length === 0) {
      throw new EpcApiError(`No EPC found for LMK key ${lmkKey}`, 404);
    }

    return { record: data.rows[0], rawBody };
  }

  private async fetchWithRetry(url: string, attempt = 0): Promise<Response> {
    const response = await this.fetchFn(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: this.authHeader,
      },
    });

    if (response.status === 429 && attempt < this.maxRetries) {
      const retryAfter = parseInt(response.headers.get('Retry-After') ?? '2', 10);
      await sleep(retryAfter * 1000);
      return this.fetchWithRetry(url, attempt + 1);
    }

    if (response.status === 404) {
      throw new EpcApiError('Certificate not found', 404);
    }

    if (!response.ok) {
      throw new EpcApiError(`EPC API error: ${response.status} ${response.statusText}`, response.status);
    }

    return response;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
