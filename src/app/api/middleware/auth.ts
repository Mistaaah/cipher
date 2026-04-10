import { Request, Response, NextFunction } from 'express';
import { errorResponse, ERROR_CODES } from '../utils/response.js';

export const apiKeyAuthMiddleware = (req: Request, res: Response, next: NextFunction) => {
	const configuredApiKey = process.env.CIPHER_API_KEY;

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
