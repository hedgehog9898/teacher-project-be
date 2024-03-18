import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { VertexAI } from '@google-cloud/vertexai';

@Injectable()
export class AppService {
  constructor(private readonly config: ConfigService) {}

  async getHello(): Promise<void> {
    const vertexAI = new VertexAI({project: 'kinetic-star-417112', location: 'us-central1'});
    const generativeVisionModel = vertexAI.preview.getGenerativeModel({
      model: 'gemini-1.0-pro-001',
      generation_config: {
        max_output_tokens: 2048,
        temperature: 0.9,
        top_p: 1
      }
    });
    const request = {
      contents: [{role: 'user', parts: [{ text: '2 + 2 = ?' }]}],
    };
    console.log('Prompt Text:');
    console.log(request.contents[0]);

    console.log('Non-Streaming Response Text:');
    // Create the response stream
    const responseStream =
      await generativeVisionModel.generateContentStream(request);

    // Wait for the response stream to complete
    const aggregatedResponse = await responseStream.response;

    // Select the text from the response
    const fullTextResponse =
      aggregatedResponse.candidates[0].content.parts[0].text;

    console.log(fullTextResponse);

    return;
  }
}
