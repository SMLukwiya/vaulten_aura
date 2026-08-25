export default async function handler(ctx) {

    if (ctx.event.source_name == 'http') {
        console.log("HTTP INVOKED");
        try {
            const res_data = await fetch("https://localhost:9443", {
                headers: {
                    "Content-type": "application/json"
                }
            })
            const data = res_data.json()
    
            return new Response(data, {status: 200, statusText: "Func1 ok"});
        } catch (err) {
            return new Response(err, {status: 500, statusText: "Func1 ok"});
        }

    } else if (ctx.event.source_name == 'cron') {
        console.log("CRON INVOKED");
        return "CRON INVOKED"
    }
}