import { Request, Response, NextFunction } from 'express';
import { errorResponse, ERROR_CODES } from '../utils/response.js';

const _cipherApiKeyRaw = process.env.CIPHER_API_KEY;
console.log(`[Auth] CIPHER_API_KEY configured: ${!!_cipherApiKeyRaw}, length: ${_cipherApiKeyRaw?.length ?? 0}`);
console.log(`[Auth] CIPHER_ env vars present: ${Object.keys(process.env).filter(k => k.startsWith('CIPHER')).join(', ') || '(none)'}`);

export const apiKeyAuthMiddleware = (req: Request, res: Response, next: NextFunction) => {
	const configuredApiKey = process.env.CIPHER_API_KEY?.trim();

	// Skip authentication for health checks
	if (req.path === '/health') {
		return next();
	}

	if (!configuredApiKey) {
		return next();
	}

	const requestApiKey = req.headers['x-api-key'] || req.query.apiKey || req.query.apikey;

	if (!requestApiKey || requestApiKey !== configuredApiKey) {
		return errorResponse(res, ERROR_CODES.UNAUTHORIZED, 'Invalid or missing API key', 401);
	}

	next();
};
