// SPDX-License-Identifier: MIT

class NetlinkWebsocket {

    constructor(
        uri,
        onConnectionEstablished,
        onConnectionClosed,
        onCommand,
        onQuery,
        onError) {

        this.onopen = () => {
            if (onConnectionEstablished) onConnectionEstablished(this);
        };

        this.onmessage = (evt) => {
            var received_msg = evt.data;
            console.log("packet received: " + received_msg);

            // 1st packet is the link ID
            if (!this.linkId) {
                this.linkId = received_msg;
                return;
            }

            try {
                const msg_packet = JSON.parse(received_msg);
                const msg_headers = JSON.parse(msg_packet.Headers);
                const msg_data = msg_packet.Data;
                if (msg_headers.response) {
                    if (this.pendingQueries.delete(msg_packet.QueryId)) {
                        const queryUUID = msg_packet.QueryId;
                        this.pendingResponses.set(queryUUID, msg_packet);
                    }
                }
                else if (msg_headers.command) {
                    if (onCommand) onCommand(this, msg_headers.command, msg_headers, msg_data);
                }
                else if (msg_headers.query) {
                    var reply = "OK";
                    if (onQuery) {
                        reply = onQuery(this, msg_headers.query, msg_headers, msg_data);
                    }
                    var payload = JSON.stringify({ Headers: { response: reply }, QueryId: msg_packet.QueryId, IsQueryResponse: true });
                    this.#SendPayload(payload);
                    console.log("Send response: " + payload);
                }
            }
            catch (error) {
                if (onError) onError(this, received_msg);
            }
        };

        this.onclose = () => {
            if ((this.ws.readyState != 0) && onConnectionClosed) onConnectionClosed(this);
        };

        this.pendingQueries = new Map();
        this.pendingResponses = new Map();

        this.uri = uri;
        //this.#Connect();
    }

    async Connect() {
        let ws = new WebSocket(this.uri);

        // Wait for connection or fail
        while (ws.readyState == 0) { // CONNECTING
            await new Promise(r => setTimeout(r, 10));
        }

        if (ws.readyState == 1) { // OPEN

            ws.onmessage = this.onmessage;
            ws.onclose = this.onclose;

            this.linkId = undefined;
            this.pendingQueries = new Map();
            this.pendingResponses = new Map();

            this.ws = ws;
            this.onopen();
        }
        else { // CLOSING or CLOSED
            this.ws = undefined;
        }
    }

    async AutoConnect() {
        while (true) {
            if (!this.IsConnected()) {
                await this.Connect();
                await new Promise(r => setTimeout(r, 4000)); // wait a few seconds before new connect attempt
            }
            else {
                await new Promise(r => setTimeout(r, 1000));
            }
        }
    }

    IsConnected() {
        return this.ws && (this.ws.readyState == 1);
    }

    #SendPayload(payload) {
        if (this.IsConnected()) {
            this.ws.send(payload);
        }
    }

    SendCommand(command) {
        var payload = JSON.stringify({ Headers: { command: command } });
        this.#SendPayload(payload);
        console.log("Send command: " + payload);
    }

    async SendQuery(query, headers = null, data = null) {
        var queryUUID = this.#generateUUID();

        if (!headers) {
            headers = new Map();
        }
        headers.set('query', query);
        var payload = JSON.stringify({ Headers: Object.fromEntries(headers), QueryId: queryUUID, IsQueryResponse: false, Data: data });
        this.pendingQueries.set(queryUUID, payload);
        this.#SendPayload(payload);
        console.log("Send query: " + payload);

        while (this.IsConnected()) {
            if (this.pendingResponses.has(queryUUID)) {
                try {
                    const msg_packet = this.pendingResponses.get(queryUUID);
                    const msg_headers = JSON.parse(msg_packet.Headers);
                    const msg_data = msg_packet.Data;
                    const msg_response = msg_headers.response;
                    return [msg_response, msg_headers, msg_data];
                }
                finally {
                    this.pendingResponses.delete(queryUUID);
                }
            }
            await new Promise(r => setTimeout(r, 100)); // TODO: Timeout
        }
    }

    #generateUUID() { // Public Domain/MIT
        var d = new Date().getTime();//Timestamp
        var d2 = ((typeof performance !== 'undefined') && performance.now && (performance.now() * 1000)) || 0;//Time in microseconds since page-load or 0 if unsupported
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.random() * 16;//random number between 0 and 16
            if (d > 0) {//Use timestamp until depleted
                r = (d + r) % 16 | 0;
                d = Math.floor(d / 16);
            } else {//Use microseconds since page-load if supported
                r = (d2 + r) % 16 | 0;
                d2 = Math.floor(d2 / 16);
            }
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        });
    }

}