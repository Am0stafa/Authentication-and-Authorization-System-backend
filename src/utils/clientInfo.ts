import { Request } from 'express';
import useragent from 'express-useragent';

interface ClientInfo {
  ipAddress: string;
  userAgent: {
    browser: string;
    version: string;
    os: string;
    platform: string;
    source: string;
  };
}

export const getClientInfo = (req: Request): ClientInfo => {
  // Get IP address with fallbacks
  const ipAddress = 
    req.clientIp || 
    req.headers['x-forwarded-for'] as string || 
    req.socket.remoteAddress || 
    'unknown';

  // Parse user agent
  const ua = req.useragent as useragent.Details;

  return {
    ipAddress: ipAddress.split(',')[0], // Get first IP if multiple
    userAgent: {
      browser: ua.browser,
      version: ua.version,
      os: ua.os,
      platform: ua.platform,
      source: ua.source
    }
  };
}; 