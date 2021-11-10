import log from 'book';
import Koa from 'koa';
import tldjs from 'tldjs';
import Debug from 'debug';
import http from 'http';
import { hri } from 'human-readable-ids';
import Router from 'koa-router';
import jwt from'koa-jwt';

var jwt_obj = require('jsonwebtoken');
import ClientManager from './lib/ClientManager';
const AWS = require("aws-sdk");
AWS.config.update({region: 'us-east-1'});
var DocumentClient = new AWS.DynamoDB.DocumentClient();

var jwt_key;
const debug = Debug('localtunnel:server');

function addJwtMiddleware(app, opt) {
    app.use(jwt({
        secret: opt.jwt_shared_secret
    }));
}

export default function(opt) {
    opt = opt || {};
    jwt_key = opt.jwt_shared_secret;
    const validHosts = (opt.domain) ? [opt.domain] : undefined;
    const myTldjs = tldjs.fromUserSettings({ validHosts });
    const landingPage = opt.landing || 'https://localtunnel.github.io/www/';

    function GetClientIdFromHostname(hostname) {
        return myTldjs.getSubdomain(hostname);
    }

    const manager = new ClientManager(opt);

    const schema = opt.secure ? 'https' : 'http';

    const app = new Koa();
    const router = new Router();

    if (opt.jwt_shared_secret){
        addJwtMiddleware(app, opt);
    }

    router.get('/api/status', async (ctx, next) => {
        const stats = manager.stats;
        ctx.body = {
            tunnels: stats.tunnels,
            mem: process.memoryUsage(),
        };
    });

    router.get('/api/tunnels/:id/status', async (ctx, next) => {
        const clientId = ctx.params.id;
        const client = manager.getClient(clientId);
        if (!client) {
            ctx.throw(404);
            return;
        }

        const stats = client.stats();
        ctx.body = {
            connected_sockets: stats.connectedSockets,
        };
    });

    router.get('/api/tunnels/:id/kill', async (ctx, next) => {
        const clientId = ctx.params.id;
        if (!opt.jwt_shared_secret){
          debug('disconnecting client with id %s, error: jwt_shared_secret is not used', clientId);
          ctx.throw(403, {
            success: false,
            message: 'jwt_shared_secret is not used'
          });
          return;
        }

        if (!manager.hasClient(clientId)) {
          debug('disconnecting client with id %s, error: client is not connected', clientId);
          ctx.throw(404, {
            success: false,
            message: `client with id ${clientId} is not connected`
          });
        }

        const securityToken = ctx.request.headers.authorization;
        if (!manager.getClient(clientId).isSecurityTokenEqual(securityToken)) {
          debug('disconnecting client with id %s, error: securityToken is not equal ', clientId);
          ctx.throw(403, {
            success: false,
            message: `client with id ${clientId} has not the same securityToken than ${securityToken}`
          });
        }

        debug('disconnecting client with id %s', clientId);
        manager.removeClient(clientId);
        // TODO  mark client id is free allow other connection

      ctx.statusCode = 200;
      ctx.body = {
        success: true,
        message: `client with id ${clientId} is disconected`
      };
    });

    app.use(router.routes());
    app.use(router.allowedMethods());

    // root endpoint
    app.use(async (ctx, next) => {
        const path = ctx.request.path;
        const key_from_header = ctx.headers.authorization.replace(/Bearer /, '');
        console.log("token from client", key_from_header);
        // skip anything not on the root path
        if (path !== '/') {
            await next();
            return;
        }

        const isNewClientRequest = ctx.query['new'] !== undefined;
        if (isNewClientRequest) {
            try {
                var decoded = jwt_obj.verify(key_from_header, '2070ba020eead9fdd71d1e8aef7872ae0fdd0b16aec4fbd90acace5b5736dfd1');
                console.log("decoded", decoded);
                var result = await getToken(decoded.tokenId);
                console.log("db result, ", result);
                if (result == undefined || Object.keys(result).length === 0) {
                    // not registered device
                    console.log("not found on database");
                    return;
                  }
                const reqId = result.Item.sub;
                debug('making new client with id %s', reqId);
                const info = await manager.newClient(reqId, opt.jwt_shared_secret ? ctx.request.headers.authorization : null);

                const url = schema + '://' + info.id + '.' + ctx.request.host;
                info.url = url;
                ctx.body = info;
                return;
            } catch(err) {
                console.log(err);
            }
            const reqId = hri.random();
            //todo remove random id with the id from the redis by checking the token parameters
            // and also mark the token is currently using the service
            debug('making new client with id %s', reqId);
            const info = await manager.newClient(reqId, opt.jwt_shared_secret ? ctx.request.headers.authorization : null);

            const url = schema + '://' + info.id + '.' + ctx.request.host;
            info.url = url;
            ctx.body = info;
            return;
        }

        // no new client request, send to landing page
        ctx.redirect(landingPage);
    });

    // anything after the / path is a request for a specific client name
    // This is a backwards compat feature
    app.use(async (ctx, next) => {
        const parts = ctx.request.path.split('/');

        // any request with several layers of paths is not allowed
        // rejects /foo/bar
        // allow /foo
        if (parts.length !== 2) {
            await next();
            return;
        }

        const reqId = parts[1];

        // limit requested hostnames to 63 characters
        if (! /^(?:[a-z0-9][a-z0-9\-]{4,63}[a-z0-9]|[a-z0-9]{4,63})$/.test(reqId)) {
            const msg = 'Invalid subdomain. Subdomains must be lowercase and between 4 and 63 alphanumeric characters.';
            ctx.status = 403;
            ctx.body = {
                message: msg,
            };
            return;
        }

        debug('making new client with id %s', reqId);
        const info = await manager.newClient(reqId, opt.jwt_shared_secret ? ctx.request.headers.authorization : null);

        const url = schema + '://' + info.id + '.' + ctx.request.host;
        info.url = url;
        ctx.body = info;
        return;
    });

    const server = http.createServer();
    // const io = require('socket.io')(server);

    const appCallback = app.callback();

    server.on('request', (req, res) => {
        // without a hostname, we won't know who the request is for
        const hostname = req.headers.host;
        if (!hostname) {
            res.statusCode = 400;
            res.end('Host header is required');
            return;
        }

        const clientId = GetClientIdFromHostname(hostname);
        if (!clientId) {
            appCallback(req, res);
            return;
        }

        const client = manager.getClient(clientId);
        if (!client) {
            res.statusCode = 404;
            res.end('404');
            return;
        }

        client.handleRequest(req, res);
    });

    server.on('upgrade', (req, socket, head) => {
        const hostname = req.headers.host;
        if (!hostname) {
            socket.destroy();
            return;
        }

        const clientId = GetClientIdFromHostname(hostname);
        if (!clientId) {
            socket.destroy();
            return;
        }

        const client = manager.getClient(clientId);
        if (!client) {
            socket.destroy();
            return;
        }

        client.handleUpgrade(req, socket);
    });

    return server;
};

function getToken(tokenId) {
    return new Promise((resolve, reject) => {
      var params = {
        TableName: 'localtunnel',
        Key: {
            tokenId
        }
      };
      DocumentClient.get(params, (err, data) => {
        if (err) {
          reject(err)
        }
        else {
          resolve(data);
        }
      });
    });
  }
