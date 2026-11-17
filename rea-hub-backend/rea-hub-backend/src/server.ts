import { app } from './app';
import { env } from './config/env';
app.listen(env.PORT, () => console.log(`REA HUB API listening on :${env.PORT}`));
