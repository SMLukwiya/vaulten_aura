// Testing js

export default async function handler(req, res) {
    console.log("Hello Vaulten aura")
    console.log("Req method: ", req.method)
    console.log("Req URL: ", req.url)

    // const res = await fetch("https://jsonplaceholder.typicode.com/todos");
    try {
        const res_data = await fetch("https://localhost:9443", {
            headers: {
                "Content-type": "application/json"
            }
        })
        const data = res_data.json()
        console.log(data)
        res.status = 200
        return res.json({message: "Right back at you!"})
    } catch (err) {
        console.error("Js catch error: ", err)
        res.status = 500
        return res.json({error: err})
    }
}